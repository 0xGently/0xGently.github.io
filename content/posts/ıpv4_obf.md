---
title: IPv4/IPv6 Obfuscation
date: 2026-02-05
draft: false
author: 0xGently
tags:
  - obfuscation
---
## IPv4/IPv6 Obfuscation

Siber güvenlik dünyasında bir veriyi saklamak istediğimizde önümüzde genellikle iki temel yol olur: Ya veriyi doğrudan şifreleriz (AES, RC4 veya XOR gibi) ya da onu karmaşıklaştırırız (obfuscation).

Yazılım geliştirirken kodu zorlaştırmak bazen sadece fikri mülkiyeti korumak için değil, güvenlik mekanizmalarını aşmak için de kritik bir rol oynar. Örneğin elimizde bir shellcode var ve bunu gizlemek istiyoruz. İlk akla gelen çözüm şifreleme olsa da bu her zaman en akıllıca yol olmayabilir. Çünkü şifrelenmiş veriler, dosyanın o bölümündeki **entropiyi (rastgelelik oranını)** tavan yaptırır ve bu durum güvenlik analizcilerinin ya da AV/EDR çözümlerinin hemen radarına takılır. İşte bu noktada, dikkat çekmeden karmaşıklaştırmak çok daha mantıklı bir seçeneğe dönüşüyor.

Peki ya bu shellcode'u alıp, sanki son derece masum bir ağ yapılandırma dosyasıymış gibi gösterebilseydik? Bu yazıda tam olarak bunu yapacağız. Shellcode'umuzu parçalara ayırıp, her bir parçayı standart bir **IPv4 adresi** (`192.168.1.1` gibi) string'ine dönüştüreceğiz. Böylece dosyamızın içinde şüpheli hex değerleri yerine, yüzlerce masum IP adresi görünecek.


**Not**: Bu metinde anlattığım kodun tamamını https://github.com/0xGently/Malware-Dev-Analysis-Library/tree/main/Payload-Encryption-and-Obfuscation/05-IPv4_IPv6_Obf adresinde bulabilirsiniz.  Ayrıca bu konunun mantığını kavrayınca diğer tekniklerin (Mac,Uuid obfuscatıon) işleyişide birebir aynı.
### 1. GeneratePkcs7Padding Fonksiyonu
 
Bir IPv4 adresi tam olarak 4 byte'tan oluşur (Örn: `192.168.1.1` -> `C0 A8 01 01`). Ancak msfvenom veya Cobalt Strike gibi araçlardan ürettiğiniz bir shellcode'un boyutunun tam olarak 4'ün katı olma garantisi yoktur. Örneğin, 275 byte'lık bir shellcode'unuz varsa ve bunu 4'erli gruplara bölerseniz en sona 3 byte kalır. Program o son IP adresini oluşturmaya çalışırken 4. byte'ı bulamayacağı için bellek hatası verir ve çöker.

Bunu önlemek için shellcode'umuzun sonunu güvenli byte'larla (padding) doldurup, toplam boyutu 4'ün tam katına eşitlememiz gerekiyor. Sadece bu işlemi yapacak bir fonksiyonumuz olacak ve bu fonksiyon, shellcode'un byte sayısını 4'ün katına tam bölünecek hale getirecek. İşlemi yapacak olan fonksiyonumuza `GeneratePkcs7Padding` adını verelim. Bu fonksiyon bizden **ham shellcode'un adresini** ve **boyutunu** alacak.


Koda geçmeden önce, işimizi kolaylaştıracak ve kodun okunabilirliğini artıracak sabitlerimizi (macro) tanımlayalım:

```go
#define IPV4_ALIGNMENT 4    // Bir IPv4 adresi oluşturmak için shellcode'dan 4 byte almalıyız
```

Şimdi `GeneratePkcs7Padding` adını verdiğimiz fonksiyonun bir kısmına bakalım:

```c
uint8_t padValue = (uint8_t)(IPV4_ALIGNMENT - (originalSize % IPV4_ALIGNMENT));
```
Diyelim ki shellcode'umuzun boyutu (`originalSize`) 275 byte olsun. `275 % 4` işlemi bize `3` kalanını verir. `4 - 3 = 1` işlemini de yaptığımızda, eklememiz gereken padding miktarının 1 byte olacağını anlıyoruz ve bu değeri `padValue` adlı değişkenimize atıyoruz.

```c
size_t newBufferSize = originalSize + padValue; // newBufferSize kadar bellek ayırıyoruz 
uint8_t* paddedBuffer = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, newBufferSize); 
if (!paddedBuffer) return NULL;
```
 Ardından orijinal boyuta bu 1 byte'ı ekleyip (`newBufferSize = 276`) bellekte yerimizi ayırıyoruz. İşte buradaki ufak bir detay hayat kurtarıyor: `HeapAlloc` fonksiyonunu **`HEAP_ZERO_MEMORY`** flag'i ile çağırdığımız için Windows bize sadece yer ayırmakla kalmıyor, o alanın içindeki tüm byte'ları otomatik olarak sıfırlıyor (`0x00`).

Biz orijinal shellcode'umuzu buraya kopyaladığımızda üzerine eklenen padding ile 276 byte olacak. Artık payload'umuz 4'e tam bölünecek şekilde hazır!

### 2. ConvertBytesToIP Fonksiyonu

Şimdi sıra, bu 4 byte'lık parçaları alıp onlardan `255.255.255.255` formatında stringler üretecek olan `ConvertBytesToIP` fonksiyonumuza geldi.

Birçok kötü yazılmış kod, her seferinde işletim sisteminden yeni bir bellek dilenir. Biz performans kaybetmemek için hafıza tahsis işini bu fonksiyonun dışına taşıyacağız. Bu fonksiyon sadece "dışarıdan verilen bir metin kutusuna (buffer)" çeviri yapacak.

Elimizdeki hex değerlerini noktalarla ayrılmış decimal sayılara çevirmek için standart C kütüphanesinin güvenli fonksiyonlarından `snprintf` veya `sprintf_s` kullanıyoruz:
```c
sprintf_s(outIpString, bufferSize, "%d.%d.%d.%d", pBytes[0], pBytes[1], pBytes[2], pBytes[3]);
```

Diyelim ki shellcode'umuzdan sırası gelen 4 byte `0xFC, 0x48, 0x83, 0xE4` olsun. `sprintf_s` fonksiyonu bu hex değerlerini sırasıyla ondalık tabana çevirir ve aralarına nokta koyarak `outIpString` içerisine yazar. Artık shellcode'umuz içerisindeki o 4 byte `252.72.131.228` IP adresine dönüşür!
### 3. PayloadIPv4Array Fonksiyonu
Hazırlık aşamalarını tamamladık; elimizde 4'ün katlarına tam bölünebilen bir veri ve bu veriyi IP adresine çeviren bir fonksiyon var. Şimdi geriye kalan tek şey, bu süreci baştan sona yönetecek, veriyi bloklar halinde okuyup ekrana basacak olan ana kontrol mekanizmasını yazmak.
```c
// 1. Padding fonksiyonumuzu çağırıp hizalanmış verimizi alıyoruz
uint8_t* paddedData = GeneratePkcs7Padding(rawData, rawSize, &paddedSize);

// 2. Kaç adet 4 byte'lık parça (chunk) elde edeceğimizi hesaplıyoruz
size_t chunkCount = paddedSize / 4;
```

İlk adımda `GeneratePkcs7Padding` fonksiyonumuzu çağırıyor ve hizalanmış veriyi doğrudan `paddedData` isimli pointer'ımıza alıyoruz. 
Hemen altındaki satırda ise basit bir matematik dönüyor: Eğer padding işlemi sonucunda elimizde 276 byte'lık hizalanmış bir veri oluştuysa, `276 / 4 = 69` işlemi sayesinde toplamda tam 69 adet IPv4 adresi (`chunkCount`) elde edeceğimizi hesaplıyoruz.


```c
// Döngü içinde sürekli bellek ayırmamak için Stack'te sabit bir alan açıyoruz
char ipStackBuffer[16]; 

// Her bir 4 byte'lık parçayı IP formatına çeviren döngümüz
for (size_t i = 0; i < chunkCount; i++)
{
    ConvertBytesToIP(&paddedData[i * 4], ipStackBuffer, sizeof(ipStackBuffer));
    
    // ... (Elde edilen string'i ekrana yazdırma işlemleri)
}
```
Açtığımız for döngüsü, toplamda elde ettiğimiz miktar kadar dönecek ve her dönüşte veriyi adım adım işleyecek. Burada en önemli detay `char ipStackBuffer[16]` satırıdır. Döngü içinde sürekli işletim sisteminden bellek isteyip programı yavaşlatmak yerine, işlemcinin yığınında (stack) 16 karakterlik sabit bir yer açarız ve her döngüde içindeki yazıyı değiştiririz. Bu, devasa bir performans ve temizlik adımıdır.

Asıl veri üzerinde gezinme işlemi ise `&paddedData[i * 4]` mantığında yatıyor. Bellekteki o ham veri yığınının içinde adım adım şunlar gerçekleşiyor:

- **Birinci adımda (i = 0):** `0 * 4 = 0` hesabı yapılır ve fonksiyona bellekteki 0. byte'ın adresi gönderilir.
- **İkinci adımda (i = 1):** `1 * 4 = 4` olur ve fonksiyon doğrudan bellekteki 4. byte'a sıçrar.
- **Üçüncü adımda (i = 2):** Doğrudan 8. byte'ın adresi okunur.
    
Bu sayede performanstan zerre ödün vermeden, bellekte tam olarak 4'er byte'lık adımlarla zıplayarak tüm shellcode'umuzu taramış oluyoruz.
### IPv6
IPv6 da karmaşıklaştırma yapmak istiyorsak yukarıda IPv4 için yapacağımız mantığın aynısını kullanmamız gerekiyor değişen neredeyse hiçbir şey yok.  Kodun mantığı veya kullanılan fonksiyonlar tamamen aynı. Tek fark bu sefer 16 ın katı olması gerektiğini ve birleştirirken `2001:0db8:85a3:0000:0000:8a2e:0370:7334` ya uyarlamanız gerektiğini unutmayın
Olayın Deobfuscation kısmını ise başka bir metinde anlatacağım. 
