---
tags:
  - obfuscation
title: Custom GetProcAddress
date: 2026-10-27
draft:
author: 0xGently
---
## Giriş

Windows sistemlerinde C veya C++ ile geliştirme yaparken, bir DLL içindeki fonksiyonu çağırmak için genellikle `GetProcAddress` kullanırız. Süreç temelde basittir: `LoadLibrary` ile DLL belleğe alınır, ardından `GetProcAddress`'e DLL'in handle değeri ve aranan fonksiyonun adı verilir. Peki bu işlem arka planda tam olarak nasıl işliyor? İşletim sistemi, verdiğimiz string değerini büyük bir bellek bloğu içinde nasıl bulup bize adresini dönüyor? Bu yazıda, standart Windows API'lerini kullanmak yerine bir PE dosyasının bellek yapısını çözümleyerek kendi `GetProcAddress` fonksiyonumuzu yazıyoruz.

Bir DLL belleğe yüklendiğinde rastgele yerleştirilmez; PE formatı kurallarına göre yapılandırılır. İşletim sistemi dosyayı diske yazarken ve belleğe alırken bu PE Header yapılarını baz alır. DLL'ler, dışa aktardıkları fonksiyonların listesini "Export Directory" adlı bir tabloda tutarlar. Orijinal `GetProcAddress`, verilen modülün bellekteki Base Address'inden yola çıkar. Önce DOS Header'ı okur, oradan NT Header'a geçer ve Export Directory'ye ulaşır. Bu dizindeki isimleri tek tek aldığı string ile karşılaştırır. Eşleşme sağlandığında, o ismin "Ordinal" değerini alır. Bu değeri kullanarak asıl adreslerin bulunduğu array'den fonksiyonun gerçek bellek adresini çeker ve bir pointer olarak döndürür. Bizim yazacağımız fonksiyon da tam olarak bu rotayı takip edecek.

Custom Fonksiyonun kendisine geçmeden önce `IMAGE_EXPORT_DIRECTORY` struct'ını incelememiz gerekiyor. 
```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;
    DWORD   AddressOfNames;
    DWORD   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

Bu yapıdaki kritik olan elemanlar şunlardır:

- **NumberOfNames:** DLL'in isimle dışa aktardığı fonksiyonların toplam sayısıdır. Döngümüzün sınırını bu değer belirleyecek.
    
- **AddressOfNames:** Fonksiyon isimlerinin  bellekteki adreslerini tutan array'dir.
    
- **AddressOfFunctions:** Fonksiyonların asıl çalıştırılabilir kodlarının bulunduğu bellek adreslerini tutan array'dir.
    
- **AddressOfNameOrdinals:** **AddressOfNames** array'i ile **AddressOfFunctions** array'i arasındaki bağlantıyı kuran Ordinal değerlerini barındırır.    

Buradaki "AddressOf" ile başlayan değerler doğrudan mutlak bellek adresi değil, RVA (Relative Virtual Address) değerleridir. RVA, bir verinin DLL'in yüklendiği Base Address'e olan uzaklığını (offset) ifade eder. Doğru adresi bulmak için sürekli olarak `Base Address + RVA` işlemini yapacağız.

Şimdi koda adım adım bakalım. İlk prensibimiz dışarıdan herhangi bir API'ye bağımlı kalmamak. `strcmp` veya `lstrcmpA` kullanmak yerine kendi custom string karşılaştırma fonksiyonumuzu yazıyoruz.
```c
BOOL CustomStringCompare(const char* str1, const char* str2) 
{
    if (!str1 || !str2) return FALSE;
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return (*str1 == *str2);
}
```

İki string pointer'ı üzerinde ilerleyip karakterleri karşılaştırıyoruz. Farklılık olana kadar veya string bitene kadar döngü devam ediyor, sonunda eşitlik durumunu döndürüyoruz.


Ana fonksiyonumuzun tanımını ve temel pointer atamasını yapıyoruz:
```c
FARPROC CustomGetProcAddress(HMODULE moduleBase, const char* apiName) 
{
    if (!moduleBase || !apiName) return NULL;
    uint8_t* baseAddr = (uint8_t*)moduleBase;
```

`moduleBase` parametresi DLL'in belleğe yüklendiği başlangıç adresidir. Bunu `uint8_t*` türüne cast ediyoruz. Amacımız RVA değerlerini eklerken C dilindeki pointer aritmetiğinin byte bazında (1 byte ilerleyerek) doğru çalışmasını sağlamak.

PE dosyasının ilk yapısı olan DOS Header'ı kontrol ediyoruz.
```c
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddr;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL; 
```

Base adresi `IMAGE_DOS_HEADER` struct'ına cast ediyoruz. DOS Header'ın `e_magic` değeri geçerli bir Windows executable dosyasında "MZ" olmak zorundadır. `IMAGE_DOS_SIGNATURE` ile bu doğrulamayı yapıyoruz.

Ardından NT Header'a geçiş yapıyoruz.
```c
    PIMAGE_NT_HEADERS ntHeaders =
     (PIMAGE_NT_HEADERS)(baseAddr + dosHeader->e_lfanew);
    
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;
```

DOS Header içindeki `e_lfanew` değeri NT Header'ın nerede başladığını gösterir. Base adres üzerine bu değeri ekleyerek NT Header'a ulaşıyoruz ve `IMAGE_NT_SIGNATURE` kontrolü ile geçerliliğini doğruluyoruz.

Export Directory'nin konumunu bulmak için Data Directory'ye erişiyoruz:
```c
IMAGE_DATA_DIRECTORY exportDataDir = 
ntHeaders > OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

if (exportDataDir.Size == 0 || exportDataDir.VirtualAddress == 0) return NULL;
```

NT Headers içindeki `OptionalHeader`'dan Export tablosunu temsil eden `IMAGE_DIRECTORY_ENTRY_EXPORT` indeksini alıyoruz. Eğer boyut veya adres sıfır ise, modül dışarıya bir fonksiyon açmıyor demektir.

Export Directory yapısını bellekte konumlandırıyoruz:
```c
PIMAGE_EXPORT_DIRECTORY exportDirectory = 
(PIMAGE_EXPORT_DIRECTORY)(baseAddr + exportDataDir.VirtualAddress);
```

Data Directory'den aldığımız RVA'yı base adres ile toplayarak doğrudan `IMAGE_EXPORT_DIRECTORY` struct'ına ulaşıyoruz.

Şimdi bu struct içindeki gerekli array'leri tanımlıyoruz:
```c
DWORD* nameArray = (DWORD*)(baseAddr + exportDirectory->AddressOfNames);
DWORD* functionArray = (DWORD*)(baseAddr + exportDirectory->AddressOfFunctions);
WORD* ordinalArray = (WORD*)(baseAddr + exportDirectory->AddressOfNameOrdinals);
```

İlgili array adreslerinin (RVA) üzerine base adresi ekleyerek array'lerin bellekteki gerçek lokasyonlarını belirliyoruz. `ordinalArray`'in  `DWORD` değil `WORD` (2 byte) tipinde olduğuna dikkat edelim.

Peki bu "Ordinal" tam olarak nedir ve neden böyle bir köprüye ihtiyaç duyuyoruz? Sistemin mantığı şu şekilde işler: `nameArray` adlı array, işletim sisteminin arama yaparken hız kazanması (ikili arama - binary search gibi algoritmaları kullanabilmesi) için alfabetik olarak sıralanmıştır. Ancak isimler alfabetik olarak dizildiğinde, bir ismin bu arraydeki sırası ile o fonksiyona ait gerçek bellek adresinin bulunduğu `functionArray` içindeki sırası doğal olarak birbirini tutmaz. İşte `ordinalArray` tam bu noktada devreye girer. Bu array `nameArray` ile tamamen paralel çalışır. Biz aradığımız fonksiyon adını `nameArray` içinde örneğin 5. sırada (`i = 5`) bulduğumuzda, o fonksiyonun asıl adresi `functionArray` içinde 5. sırada değildir. Gerçek indeksi öğrenmek için köprü görevi gören `ordinalArray[5]` değerine bakarız. Oradan çıkan değer (ordinal), fonksiyonun adres dizisindeki asıl yerini gösterir. Özetle ordinal, alfabetik isim listesi ile bellek adres listesi arasındaki hizalamayı sağlayan bir indeks haritasıdır.

Bu mantığı anladıktan sonra, fonksiyon isimleri arasında arama yapacağımız döngüyü kuruyoruz:
```c
    DWORD totalNames = exportDirectory->NumberOfNames;
    for (DWORD i = 0; i < totalNames; i++) 
    {
        char* currentFuncName = (char*)(baseAddr + nameArray[i]);
```

`NumberOfNames` değeri kadar dönen bir döngü başlatıyoruz. Her adımda `nameArray` içindeki RVA değerini base adrese ekleyerek o anki fonksiyon adının bellek adresini elde ediyoruz.

Hedef API adıyla karşılaştırma işlemini ve ordinal kullanımını gerçekleştiriyoruz:
```c
        if (CustomStringCompare(apiName, currentFuncName)) 
        {
            WORD ordinalIndex = ordinalArray[i];
            
            FARPROC targetFunction =
             (FARPROC)(baseAddr + functionArray[ordinalIndex]);
            
            return targetFunction;
        }
    }
    return NULL;
}
```
Kendi string fonksiyonumuzla eşleşme durumunu kontrol ediyoruz. Eşleşme sağlandığında, az önce bahsettiğimiz köprü mantığını işletiyoruz: Döngüdeki `i` indeksini kullanarak `ordinalArray` üzerinden fonksiyonun gerçek sıra numarasını (`ordinalIndex`) alıyoruz. Bu sıra numarasını `functionArray` üzerinde indeks olarak kullanıp asıl fonksiyonun RVA değerini çekiyoruz. Son olarak bu RVA'yı base adres ile toplayarak hedef fonksiyonun çalıştırılabilir bellek adresine (FARPROC) ulaşıyoruz ve döndürüyoruz. Döngü bittiğinde hiçbir eşleşme bulunmazsa NULL dönüyoruz.

Bu işlemler sonucunda standart bir Windows API'si olan `GetProcAddress`'in arka plandaki PE Header parse işlemlerini kendi kodumuzla uygulamış olduk. Orijinal `GetProcAddress` fonksiyonu, bu temel yapının yanı sıra "Forwarded Exports" (bir DLL içindeki fonksiyonun farklı bir DLL'e yönlendirilmiş olması) gibi istisnai durumları da yönetmektedir. Ancak bellek üzerindeki RVA hesaplamalarını, Ordinal köprüsünü ve PE dosya yapısını kavramak için bu temel uygulamayı adım adım yazmak, mimariyi anlamak açısından oldukça verimlidir. İşlemi dış bağımlılıklar olmadan, doğrudan bellek adresleri üzerinden tamamlamış olduk.

Konuda anlatılan kodun tamamına ulaşmak isterseniz [malware-development-library](https://github.com/0xGently/malware-development-library/tree/main/IAT-Hiding/GetProcAddress) adresinden ulaşabilirsiniz.
