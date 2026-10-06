---
title: " Process Enumeration"
date: 2026-02-03
draft:
author: 0xGently
tags:
  - Enumeration
---
## Process Enumeration 
### Hedefin PID Değerini Bulmak (EnumProcesses)

Zararlı yazılım geliştirirken payload'umuzu saklamak veya çalıştırmak gibi teknikleri uygulayabilmek için genellikle sistemde çalışan meşru bir process'e (örneğin `notepad.exe` veya `explorer.exe`) ihtiyaç duyarız. Windows'un dilinden konuşup o process'in PID (Process ID) değerini bulmamız gerekir.

İşte sistemdeki süreçleri listeleyip hedefimizin PID değerini bulma veya buna benzer processler ile ilgili bilgi toplama işlemlerine genel olarak **Process Enumeration** diyoruz. Bu yazıda, Windows'un standart `EnumProcesses` API'sini kullanarak bunu sıfırdan nasıl yapacağımıza adım adım bakacağız.

Öncelikle tüm olayı tek bir çatı altında toplayan fonksiyonumuza bakalım:
```c
BOOL FindSystem32Process(const wchar_t* target_name, DWORD* out_pid)
```
Gördüğünüz gibi Bool türünde bir fonksiyon. Kendisi içerisinde 2 adet parametre bulunduruyor.
1.si Hedeflediğimiz processin ismini istiyor( örn: svchost.exe).
2.si Hedef olarak belirlediğimiz processin Pid sini dışarı atıyor.

Fonksiyonun devamında ise böyle bir kısım var:
```c
DWORD pids[2048], bytes;
if (!EnumProcesses(pids, sizeof(pids), &bytes)) return FALSE;
```

Burada `pids` adında bir array (dizi) oluşturuyoruz. `EnumProcesses` API'si, sistemdeki tüm aktif PID'leri çekip bu array'in içine dolduruyor. `bytes` değişkeni ise bu array'in içine ne kadar veri yazıldığını tutuyor. Artık elimizde sistemdeki tüm süreçlerin PID'lerini içeren devasa bir havuz var.


Şimdi bu havuzun içindeki PID'leri tek tek dolaşıp hedeflediğimiz gerçek processi bulmamız lazım. Bunun için bir döngü başlatıyoruz:

```c
for (DWORD i = 0; i < bytes / sizeof(DWORD); i++) {
    if (!pids[i]) continue;

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
    if (!h) continue;
```

Döngü her döndüğünde sıradaki PID'yi alıp `OpenProcess` API'si ile açmaya çalışıyoruz. Burada dikkat etmeniz gereken çok önemli bir nokta var: Hedef process'i açarken talep ettiğimiz yetki. Bizim sadece process'in ismini okumaya ihtiyacımız olduğu için `PROCESS_QUERY_LIMITED_INFORMATION` yetkisi istiyoruz. Eğer gereksiz yere `PROCESS_ALL_ACCESS` (tam erişim) isteseydik, bu güvenlik çözümleri (EDR/AV) için oldukça şüpheli bir hareket olurdu. Handle (`h`) başarıyla alınırsa, artık o sürecin içine bakabiliriz.

Handle elimizde, şimdi bu PID'nin arkasında hangi uygulamanın çalıştığını öğrenme vakti.
```c
wchar_t path[MAX_PATH];
DWORD size = MAX_PATH;
```
- **`wchar_t`**: Windows API'lerinin sonunda `W` (Wide) olan fonksiyonlarını kullandığımız için, normal `char` (1 byte) yerine Unicode destekleyen `wchar_t` (2 byte geniş karakter) kullanmak zorundayız.
    
- **`MAX_PATH`**: Bu, Windows işletim sisteminin başlık dosyalarında (header) tanımlanmış standart bir makrodur ve değeri **260**'tır. Windows'ta klasik bir dosya yolunun alabileceği maksimum karakter sınırını belirtir. Yani `path` adında, içine en fazla 260 karakter sığabilecek boş bir dizi (kutu) oluşturuyoruz.
    
- **`size`**: API'ye "Benim elimde 260 karakterlik yer var" diyebilmek için bu değeri `DWORD` (32-bit işaretsiz tam sayı) tipinde bir değişkene atıyoruz.
```c
if (QueryFullProcessImageNameW(h, 0, path, &size)) {
```
- Bu fonksiyon, process handle'ını (`h`) alıp, tam dosya yolunu az önce oluşturduğumuz `path` dizisinin içine yazar.
    
- Buradaki mucizevi olay `&size` kısmıdır. `size` değişkenini doğrudan değil, başına `&` koyarak **bellek adresiyle (referans olarak)** gönderiyoruz. Neden? Çünkü API işini bitirdiğinde, "Sen bana 260 karakterlik yer verdin ama ben bunun sadece 35 karakterini kullandım" diyerek, o process yolunun **gerçek uzunluğunu** doğrudan bu değişkenin içine geri yazar (In/Out parameter mantığı).
    
- Eğer bu işlem hatasız gerçekleşirse fonksiyon `TRUE` (1) döndürür ve `if` bloğunun içine gireriz.
```c
wchar_t* name = wcsrchr(path, L'\\');
```
- **`wcsrchr` (Wide Character String Reverse Character):** C standart kütüphanesindeki string arama fonksiyonudur. Amacı bir string'i soldan sağa değil, **sağdan sola (sondan başa)** doğru taramaktır.
    
- **`L'\\'`**: Aradığımız karakter ters slash. C dilinde `\` bir kaçış (escape) karakteri olduğu için, kendisini ifade etmek için iki tane yazılır `\\`. Başındaki `L` ise bunun bir geniş karakter (Unicode) olduğunu belirtir.
    
- Diyelim ki `path` içindeki veri şu: `C:\Windows\System32\notepad.exe`. `wcsrchr` en sağdan başlar, `e`, `x`, `e`, `.`, `d`... diye gider ve ilk gördüğü `\` işaretinde durur.
    
- Geriye bir string değil, o ters slash'ın bulunduğu noktanın **bellek adresini (pointer)** döndürür. Yani `name` pointer'ı artık tam olarak `\notepad.exe` kısmını işaret etmektedir.
```c
name = name ? name + 1 : path;
```

Bu satır C dilinin meşhur üçlü operatörünü (`koşul ? doğruysa_bu : yanlışsa_bu`) ve pointer aritmetiğini barındırır.

- **`name ?`**: "Eğer `name` boş değilse (yani bir ters slash bulabildiysek)" anlamına gelir.      
    
- **`name + 1`**: İşte işin koptuğu yer burası. `name` pointer'ı `\notepad.exe` string'inin başındaki `\` işaretini gösteriyordu. Biz bellek adresini `+ 1` diyerek bir karakter sağa kaydırıyoruz. Böylece o baştaki slash'ı atlamış oluyoruz ve pointer sadece `notepad.exe` kısmını göstermeye başlıyor. Saf dosya adını böyle izole ediyoruz.
    
- **`: path`**: Eğer `wcsrchr` hiçbir ters slash bulamazsa (bu teknik olarak pek mümkün değil ama güvenli kod yazma kuralıdır), `name` pointer'ı `NULL` döner. Bu durumda koşul yanlış (false) sayılır ve iki nokta üst üste (`:`) sonrasındaki işlem yapılır: Elimizde ne varsa (orijinal `path`) onu saf isim olarak kabul et.

  
Son aşamada, bulduğumuz ismin bizim aradığımız hedefle eşleşip eşleşmediğine bakıyoruz.
```c
        if (_wcsicmp(name, target_name) == 0) {
            *out_pid = pids[i];
            CloseHandle(h);
            return TRUE;
        }
    }
    CloseHandle(h);
}
```
`_wcsicmp` ile büyük/küçük harf duyarlılığına takılmadan elimizdeki ismi aradığımız `target_name` ile karşılaştırıyoruz. Eğer eşleşiyorsa hedefi bulduk demektir! PID değerini dışarı aktarıyor (`*out_pid = pids[i]`), açık olan handle'ı temizliyor (`CloseHandle`) ve aramamızı başarıyla bitiriyoruz. Eğer eşleşmezse, döngü bir sonraki PID'yi incelemek üzere devam ediyor.

**Not**: Bu metinde anlattığım kodun tamamını https://github.com/0xGently/Malware-Dev-Analysis-Library/blob/main/Enumeration/EnumProcesses/EnumProcesses.c adresinde bulabilirsiniz