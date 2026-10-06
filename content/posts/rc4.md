---
title: RC4 Şifreleme
date: 2026-04-20
draft: false
author: 0xGently
tags:
  - encryption
---
## RC4 Şifrelemesi

RC4, veriyi bloklar halinde değil, bayt bayt şifreleyen simetrik bir akış şifrelemesi (stream cipher) algoritmasıdır. Arka planda iki temel aşamadan oluşur: Anahtarın bellekte karıştırıldığı **KSA (Key-Scheduling Algorithm)** ve şifrelenecek verinin üzerine yazılacak rastgele baytların üretildiği **PRGA (Pseudo-Random Generation Algorithm)**. Simetrik yapısı sayesinde aynı fonksiyon hem şifreleme hem de deşifreleme için kullanılır.

Zararlı yazılım geliştirmede RC4'ü koda entegre etmek için temelde 3 yöntem kullanılır:

1. **SystemFunction032:** `Advapi32.dll` içerisinde bulunan, Windows tarafından belgelenmemiş (undocumented) RC4 API'sidir.
    
2. **SystemFunction033:** `SystemFunction032` ile birebir aynı parametreleri alan ve aynı işlemi yapan alternatif belgelenmemiş API'dir. Aralarında pratikte hiçbir fark yoktur.
    
3. **Custom RC4:** Herhangi bir Windows API'sine bağlı kalmadan algoritmanın sıfırdan yazıldığı yöntemdir.
    

Aşağıdaki yapı, Windows'un içindeki `SystemFunction032` (veya 033) kullanılarak nasıl bu işlemi yapabiliriz onu göstermektedir.
### 1. Gerekli Structlar
`SystemFunction032` belgelenmemiş bir API olduğu için doğrudan bir byte dizisi (`PBYTE`) kabul etmez. Kendi içerisinde `USTRING` (veya `UNICODE_STRING`/`ANSI_STRING`) benzeri belirli bir struct yapısı bekler.
```c
typedef struct _RC4_CTX {
    DWORD BufferSize;
    DWORD MaxBufferSize;
    PVOID pBufferData;
} RC4_CTX, *PRC4_CTX;
```

Kodda `_RC4_CTX` olarak tanımlanan bu struct, API'nin beklediği bellek düzenini sağlar. Hem şifreleme anahtarı (key) hem de hedef veri (payload) işlemden geçirilmeden önce bu struct formatına sarılmak zorundadır.
### 2. Execution Flow
Bu yöntemde API doğrudan dahil edilmez (Import Table'da görünmemesi için). Bunun yerine dinamik olarak resolve edilir:
```c
typedef NTSTATUS(WINAPI* PFN_SYS_FUNC_032)(PRC4_CTX pData, PRC4_CTX pKey);
```

API'nin bellek adresi bulunduğunda onu tetikleyebilmek için uygun bir fonksiyon pointer'ı (`PFN_SYS_FUNC_032`) tanımlanır.

**İşlem Zinciri:**

1. **Struct Hazırlığı:** `rc4Key` ve `rc4Data` değişkenleri oluşturularak, ham bellek adresleri ve boyutları yukarıda tanımlanan struct içerisine yerleştirilir.
```c
RC4_CTX rc4Key = { keySize, keySize, keyBuffer }; 
RC4_CTX rc4Data = { payloadSize, payloadSize, payloadBuffer };    
```  
    
2. **DLL Yükleme:** `LoadLibraryA("Advapi32.dll")` ile API'yi barındıran kütüphane process belleğine çekilir.
	
```c
HMODULE hLib = LoadLibraryA("Advapi32.dll");
```
    
4. **Adres Çözümleme:** `GetProcAddress` ile `SystemFunction032`'nin bellekteki tam konumu bulunur.
    ```c
    PFN_SYS_FUNC_032 SysFunc032 = (PFN_SYS_FUNC_032)GetProcAddress(hLib, "SystemFunction032");
    ```
    
5. **Çalıştırma:** Bulunan adres ilgili fonksiyon pointer'ına dönüştürülür ve çalıştırılır: 
```c
SysFunc032(&rc4Data, &rc4Key)
```

İşlem sonucunda `payloadBuffer` içindeki veri bellekte doğrudan şifrelenmiş (veya zaten şifreliyse çözülmüş) olur.

Şimdi ise Custom olara rc4 şifrelemeyi nasıl yapacağımıza bakalım.
### Custom RC4

API Hooking gibi Blue Team engellerine takılmamak için en güvenli yöntem, RC4 algoritmasını hiçbir dış DLL'e veya Windows API'sine ihtiyaç duymadan sıfırdan koda gömmektir.

**Not**: Aşağıda incelenen RC4 algoritmasının temel C implementasyonu https://www.oryx-embedded.com/doc/rc4_8c_source.html Oryx Embedded  tarafından geliştirilen açık kaynaklı CycloneCRYPTO kütüphanesinden alınmıştır.

RC4 algoritması matematiksel olarak iki ana  (fonksiyondan) oluşur. Tüm işlem, `S-box` adı verilen 256 baytlık bir durum dizisi (state array) üzerinde gerçekleşir.

Öncelikle bu şifreleme işlemi sırasında değerleri hafızada tutabilmek için kendimize bir yapı (`struct`) hazırlıyoruz:
```c
typedef struct _RC4_STATE {
    unsigned char stateArray[256];
    int iter1;
    int iter2;
} RC4_STATE;
```
- `stateArray[256]`: Tüm şifreleme/çözme işleminin üzerinden döneceği, 256 baytlık asıl tablomuz (S-box).
    
- `iter1` ve `iter2`: Az sonra döngülerde kullanacağımız ve nerede kaldığımızı takip edecek olan basit sayaçlar.
    
### Tabloyu Hazırlama ve Karıştırma (KSA)

Struct'ımızı oluşturduktan sonra `PrepareRc4` fonksiyonu ile asıl işleme geçiyoruz. Bu fonksiyon bizden şifrelemeyi başlatmak için 3 temel bilgi istiyor: Doldurulacak boş tablomuz (`rc4Obj`), belirlediğimiz şifre (`secretKey`) ve bu şifrenin uzunluğu (`keySize`).
```c
void PrepareRc4(RC4_STATE* rc4Obj, const unsigned char* secretKey, size_t keySize) 
{
    int i, j = 0;
    unsigned char temp;

    // 1. Adım: Tabloyu Sıralı Doldurma
    for (i = 0; i < 256; i++) {
        rc4Obj->stateArray[i] = i;
    }

    // 2. Adım: Şifre ile Tabloyu Karıştırma
    for (i = 0; i < 256; i++) {
        // Matematiksel karıştırma formülü
        j = (j + rc4Obj->stateArray[i] + secretKey[i % keySize]) % 256;

        // Swap (Yer Değiştirme) işlemi
        temp = rc4Obj->stateArray[i];
        rc4Obj->stateArray[i] = rc4Obj->stateArray[j];
        rc4Obj->stateArray[j] = temp;
    }
}
```

**Bu kod blokları adım adım ne yapıyor?**
1. **İlk Adım (Deste Dizme):** 256 baytlık `stateArray` tablomuzun içini sırayla `0, 1, 2... 255` sayılarıyla dolduruyoruz. Bunu henüz karıştırılmamış, yeni açılmış sıralı bir iskambil destesi gibi düşünebilirsiniz.
    
2. **İkinci Adım (Desteyi Karma):** Karmaşık görünen asıl kısım burasıdır. Kod, az önce oluşturduğumuz o sıralı desteyi alır ve bizim verdiğimiz `secretKey`'i kullanarak matematiksel olarak karmakarışık hale getirir.
    
    - Formül (`j = ...`), destedeki elemanların bizim şifremize göre rastgele bir indeks üretmesini sağlar. `% 256` yapılması, dizinin boyutundan (256) dışarı taşıp programı çökertmemesi içindir.
        
    - Hemen altındaki `temp` değişkeniyle yapılan işlem ise klasik bir **Swap (Yer Değiştirme)** hareketidir. Seçilen iki sayının tablodaki yerleri birbiriyle değiştirilir.
        

`PrepareRc4` fonksiyonu işini bitirdiğinde, elimizde bizim `secretKey`'imize özel olarak tamamen rastgele dizilmiş, entropisi yüksek 256 baytlık bir `stateArray` tablosu oluşur.

### Şifreleme Fonksiyonu (PRGA)

Bir önceki evrede tablomuzu (destemizi) hazırlayıp şifremize göre karmakarışık hale getirmiştik. Şimdi `Rc4Cipher` fonksiyonu ile asıl verimizi şifreleme aşamasına geçiyoruz.


**1. Adım: Context Restore**
```c
void Rc4Cipher(RC4_STATE* rc4Obj, const unsigned char* input, unsigned char* output, size_t length) 
{
    unsigned char temp;

    
    unsigned int i = rc4Obj->iter1;
    unsigned int j = rc4Obj->iter2;
    unsigned char* s = rc4Obj->stateArray;

```
Burada yaptığımız şey çok basit: KSA evresinde  oluşturduğumuz o karmakarışık tabloyu (`s`) ve nerede kaldığımızı tutan sayaçları (`i` ve `j`) struct'ın içinden çekip alıyoruz.

**2. Adım: Encryption Loop**
Şimdi ise yukarıda tamamladığımız hazırlıktan sonra asıl payloadı şifreleyecek kısma geçiş yapıyoruz
```c
    // Asıl Şifreleme/Çözme Döngüsü
    while (length > 0) 
    {
        // 1. Adım: İndeksleri Kaydırma
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        // 2. Adım: Swap (Desteyi karıştırmaya devam et)
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        // 3. Adım: Rastgele Bayt Üretme ve XOR İşlemi
        *output = *input ^ s[(s[i] + s[j]) % 256];

        // 4. Adım: Sonraki bayta geçiş
        input++;
        output++;
        length--;
    }

    // İşlem bittiğinde son durumu struct içine geri kaydediyoruz
    rc4Obj->iter1 = i;
    rc4Obj->iter2 = j;
}

```
İşte bu döngü adım adım şöyle çalışıyor:

1. **Kaydırma ve Swap:** Döngü her döndüğünde, o hazırladığımız karışık deste sabit kalmaz. `i` ve `j` sayaçları ilerler ve tablonun içindeki iki eleman sürekli birbiriyle yer değiştirir (Swap). Yani şifreleme işlemi boyunca destemiz karıştırılmaya devam eder.
2. **XOR ile Şifreleme:** Kodun kalbi `*output = *input ^ s[(s[i] + s[j]) % 256];` satırıdır. Tablodan tamamen rastgele görünen bir bayt çekilir ve zararlı yazılımımızın o anki baytı (`*input`) ile **XOR** işlemine sokulur. Çıkan şifreli sonuç direkt `output` alanına yazılır.
3. **Kaydetme:** İşlem bittiğinde (tüm payload şifrelendiğinde), sayaçların (`i` ve `j`) son hali tekrar struct'a kaydedilir ki, ileride bu fonksiyona tekrar işimiz düşerse destede nerede kaldığımızı bilelim.

Bu şekilde aslında custom olarak kendi RC4 fonksiyonumuzun temel iskeletini oluşturduk. Bundan sonrasında kodda ekstra değişiklikler yapmak veya kodun tamamını okuyabilmek için yukarıdaki paylaşmış olduğum CycloneCRYPTO kütüphanesine bakabilirsiniz.

**NOT**: Güvenlik yazılımlarının standart RC4 döngü imzalarını tespit etmesini zorlaştırmak için algoritma üzerinde küçük modifikasyonlar yapılabilir. Örneğin, S-box boyutu `256` yerine `512` yapılabilir veya XOR işleminden hemen sonra her bayta `+1` eklemek ya da bit kaydırmak (Bitwise Rotation) gibi **Custom XOR** yöntemleri eklenerek statik analiz motorlarının işi daha da zorlaştırılabilir.