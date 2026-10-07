---
title: Process Enumeration
date: 2026-10-08
draft: false
author: 0xGently
tags:
  - enumeration
---
## Process Enumeration 
### Hedefin PID Değerini Bulmak (NtQuerySystemInformation) 

Zararlı yazılım geliştirirken (malware dev), payload'umuzu bellekte saklamak veya **Birçok** Execute tekniklerini stabil bir şekilde çalıştırabilmek için genellikle sistemde zaten var olan meşru bir process'e (örneğin `notepad.exe`, `explorer.exe` veya `svchost.exe`) ihtiyaç duyarız.

İşte tam bu noktada, sistemde o an aktif olan süreçleri listeleyip hedefimizin PID değerini koparmaya veya süreçler hakkında telemetry toplamaya genel olarak **Process Enumeration** diyoruz. Bir önceki yazımızda, Windows’un standart `EnumProcesses` API'sini kullanarak bu işlemi sıfırdan nasıl yapacağımıza adım adım bakmıştık. Ancak siber güvenlik dünyasında her zaman daha karmaşık daha öğrenilmesi zor yollar var...

Bu yazıda ise rotamızı çok daha derine kırıp, doğrudan `ntdll.dll` içerisinde saklanan belgelenmemiş (undocumented) **`NtQuerySystemInformation`** fonksiyonuna çeviriyoruz. Bunu yapmamızın sebebi ise AV ve EDR gibi güvenlik mekanizmaları. Modern güvenlik ürünleri, Windows'un yüksek seviyeli (high-level) DLL dosyalarına ve API'lerine **hook** atarak onları çok sıkı izler. Hatta sadece izlemekle kalmaz, şüpheli gördükleri çağrıları yeri geldiğinde manipüle edip operasyonumuzu daha başlamadan baltalayabilirler. İşte bu yüzden, bu kancalara yakalanmamak ve tespit radarlarının altından uçabilmek için ne kadar **low-level** takılırsak o kadar iyi.

**İlk adım**, ntdll modülünün handle'ını almak:
```c
HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
```
Burada `LoadLibrary` kullanmıyoruz çünkü `ntdll.dll` her process'te zaten belleğe yüklü durumda — Windows'ta hiçbir process onsuz başlayamıyor. `GetModuleHandle` sadece zaten yüklü olan modülün referansını veriyor, ekstra bir yükleme işlemi gerekmiyor.

**İkinci adımda** fonksiyonun adresini çözümlüyoruz:
```c
PFN_NtQuerySystemInformation NtQuerySystemInformation =
    (PFN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
```

Bu fonksiyon resmi olarak Microsoft tarafından dokümante edilmediği için statik olarak linklenemiyor — `ntdll.lib` içinde ismen var ama prototipi header dosyalarında eksik ya da hiç yok. Bu yüzden fonksiyonu çalışma zamanında, kendi tanımladığımız bir function pointer tipiyle çözümlememiz gerekiyor:

```c
typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);
```
Bu satırda derleyiciye henüz resmi olarak tanımadığı bu fonksiyonun **şablonunu** öğretiyoruz. Parametre parametre ne işe yaradığına bakarsak:
- **`typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)`**: Derleyiciye, geriye `NTSTATUS` (hata/başarı kodu) döndüren `PFN_NtQuerySystemInformation` adında yeni bir fonksiyon tipi tanımladığımızı söyler.
- **1. Parametre (`ULONG`)**: Kernel'dan hangi tür sistem bilgisini istediğimizi belirttiğimiz sayıdır. Biz süreç listesini çekmek için `SystemProcessInformation` yani `5` değerini göndereceğiz.
- **2. Parametre (`PVOID`)**: Kernel'ın sistem bilgilerini içerisine yazacağı, bizim önceden ayırdığımız boş bellek alanının (Buffer) adresidir.
- **3. Parametre (`ULONG`)**: Kernel'a verdiğimiz bu bellek alanının byte cinsinden boyutudur.
- **4. Parametre (`PULONG`)**: Eğer verdiğimiz bellek miktarı yetersiz kalırsa, Windows kernel'ının bize _"Bana aslında şu kadar byte bellek gerekiyor"_ diye gerçek ihtiyacını yazıp geri fırlatacağı değişkenin adresidir.


`GetProcAddress` başarısız dönerse, (yani `ntdll.dll`dosyasını bulamamak veya hedef fonksiyonu bulamamak veya herhangi bir problem olursa) fonksiyonu hiç kullanmadan direkt çıkış yapıyoruz.

```c
if (!NtQuerySystemInformation) return FALSE;
```

Bu kontrol pratikte neredeyse hiç tetiklenmiyor çünkü ntdll ve bu fonksiyon Windows'un her sürümünde mevcut, ama savunmacı programlama açısından atlanmaması gereken bir adım.


`NtQuerySystemInformation`'ı çağırmadan önce karşımıza çıkan ilk zorluk şu: sistemdeki tüm süreçlerin bilgisini tutacak buffer alanının  ne kadar büyük olması gerektiğini önceden bilmiyoruz. Sistemde o an kaç süreç çalıştığı sürekli değişebiliyor, dolayısıyla "şu an N tane süreç var, ona göre N kere struct boyutunda bellek ayırayım" mantığı kurulamaz. Hatta ve hatta daha biz buffer alanını oluştururken sistem içerisinde yeni processler de başlayabilir.

Bu problemi çözmek için dene-büyüt-tekrar dene mantığıyla çalışan bir döngü kuruyoruz. Önce makul bir başlangıç boyutu belirliyoruz:

```c
ULONG size = 1 << 16; // 64 KB başlangıç tahmini
PVOID buffer = NULL;
NTSTATUS status;
```

Döngünün her adımında önce bir önceki tamponu serbest bırakıp yenisini ayırıyoruz:

```c
do {
    if (buffer) HeapFree(GetProcessHeap(), 0, buffer);
    buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!buffer) return FALSE;
```

`HeapAlloc` kullanıyoruz, `malloc` değil — çünkü doğrudan process heap'i üzerinde çalışıyoruz ve `HEAP_ZERO_MEMORY` flag'i ile ayrılan belleği sıfırlıyoruz, bu da struct içindeki kullanılmayan alanların rastgele değerler taşımasını engelliyor.

Ardından asıl çağrıyı yapıyoruz:

```c
    status = NtQuerySystemInformation(SystemProcessInformation, buffer, size, &size);
    if (status == STATUS_INFO_LENGTH_MISMATCH) size += (1 << 14);
} while (status == STATUS_INFO_LENGTH_MISMATCH);
```

Burada iki kritik nokta var. Birincisi, `size` parametresinin hem girdi hem çıktı olarak kullanılması: fonksiyona "bu kadar yerim var" diye gönderiyoruz (3. parametre), fonksiyon da "bana aslında bu kadar yer lazımdı" diye aynı değişkene yazıyor(4. parametre). 
İkincisi, `STATUS_INFO_LENGTH_MISMATCH` durumunda sadece fonksiyonun bildirdiği boyutu değil, üzerine ekstra 16 KB daha ekliyoruz. Bunun nedeni şu: Biz bu döngüyü çalıştırdığımız zaman birkaç milisaniye içinde bile sistemde yeni süreçler başlamış olabilir, dolayısıyla tam ihtiyaç duyulan boyutu versek bile bir sonraki çağrıda yine yetersiz kalma ihtimali var. Bu pay, ikinci bir mismatch turunu büyük ölçüde önlüyor.

Döngü, `STATUS_INFO_LENGTH_MISMATCH` dönmeyi bıraktığında sona eriyor. Son olarak gerçek bir hata durumunu kontrol ediyoruz:

```c
if (!NT_SUCCESS(status)) {
    HeapFree(GetProcessHeap(), 0, buffer);
    return FALSE;
}
```

`NT_SUCCESS` makrosu, NTSTATUS değerinin başarı aralığında olup olmadığını kontrol ediyor. Tabi burada hata dönerse, daha önce ayırdığımız alanı serbest bırakmayı unutmuyoruz.

Bu noktada elimizde `buffer` içinde tüm sistem süreçlerinin bilgisini tutan, doğru boyutlandırılmış bir bellek alanı var.


`NtQuerySystemInformation`'dan dönen veri, klasik bir dizi değil. Her `SYSTEM_PROCESS_INFORMATION` kaydı ve bir sonraki kayda  byte cinsinden ofseti kendi içinde taşıyor. Yani aslında elimizde linked-list mantığıyla çalışan, ama bellek üzerinde art arda duran bir yapı var. İlk elemana işaret ederek başlıyoruz:

```c
PSYSTEM_PROCESS_INFORMATION entry = (PSYSTEM_PROCESS_INFORMATION)buffer;
```

Ve sonsuz döngü içinde `NextEntryOffset` alanını kullanarak ilerliyoruz:

```c
if (entry->NextEntryOffset == 0) break;
entry = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)entry + entry->NextEntryOffset);
```

`NextEntryOffset` sıfır olduğunda listenin son elemanına geldiğimiz anlamına geliyor, döngüden çıkıyoruz. Burada işaretçi aritmetiğini `PBYTE`'a cast ederek yapıyoruz, çünkü ofset byte cinsinden veriliyor. `entry` tipinde pointer aritmetiği yapsaydık struct boyutu kadar atlardık, ki bu yanlış olurdu.

Her kayıt içinde sürecin adı `ImageName` alanında bir `UNICODE_STRING` olarak tutuluyor. Karşılaştırmayı yapmadan önce bir güvenlik kontrolü gerekiyor, çünkü Idle ve System gibi bazı özel süreçlerde bu alan boş olabiliyor:
```c
if (entry->ImageName.Buffer && _wcsicmp(entry->ImageName.Buffer, target_name) == 0) {
```

`_wcsicmp` kullanıyoruz çünkü karşılaştırma case-insensitive olmalı. Windows dosya sistemi büyük/küçük harf duyarsız çalışıyor, dolayısıyla `System.exe` ile `system.exe` aynı süreç olarak değerlendirilecek.


İsim eşleşmesi tek başına yeterli değil. Biri `C:\Users\Public\notepad.exe` gibi bir yere, sistem sürecininkiyle birebir aynı isimde bir binary koyarsa, sadece isme bakan bir kontrol bunu meşru bir hizmet sanır. Bu yüzden eşleşen her PID için gerçek disk yolunu da doğruluyoruz.

Önce PID'yi struct'tan çıkarıyoruz:

```c
DWORD pid = (DWORD)(ULONG_PTR)entry->UniqueProcessId;
```

`UniqueProcessId` aslında bir `HANDLE` tipinde tanımlı ama gerçekte bir PID değeri taşıyor. Bu yüzden önce `ULONG_PTR`'a, sonra `DWORD`'a cast ediyoruz.

Path bilgisini almak için süreci açmamız gerekiyor, ama burada en kritik kurallardan birine geliyoruz: asla `PROCESS_ALL_ACCESS` istemiyoruz.

```c
HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
```

`PROCESS_QUERY_LIMITED_INFORMATION`, Windows Vista ile gelen ve sürece herhangi bir müdahale izni vermeyen, sadece sorgulama amaçlı en düşük seviye erişim hakkı. `QueryFullProcessImageNameW` gibi fonksiyonlar için bu yeterli. `PROCESS_ALL_ACCESS` istemek hem gereksiz hem de normal bir programın neden bu kadar geniş yetkiye ihtiyaç duyduğu şüphesini doğurur ki bu olmaması gereken bir durum.

Handle başarıyla açıldıysa, gerçek disk yolunu sorguluyoruz:

```c
WCHAR path[MAX_PATH];
DWORD len = MAX_PATH;
if (QueryFullProcessImageNameW(hProc, 0, path, &len) &&
    _wcsnicmp(path, sysDir, sysDirLen) == 0 && path[sysDirLen] == L'\\') {
    *out_pid = pid;
    found = TRUE;
}
```

Burada iki şartı birden arıyoruz: İlk olarak `_wcsnicmp` fonksiyonuyla dosya yolunun (path) başlangıcının `sysDir` (yani `C:\Windows\System32`) ile uyuşup uyuşmadığına bakıyoruz. Hemen ardından ise `path[sysDirLen]` konumunda bir `\` karakteri gelip gelmediğini kontrol ediyoruz.

Eğer bu ikinci kontrolü yapmazsak, basit bir string eşleşmesini aldatmak için oluşturulmuş `C:\Windows\System32Config\update.exe` veya `C:\Windows\System32-Drivers\update.exe` gibi yollar da prefix (önek) eşleşmesinden dolayı bu filtreden kaçabilir. Karakter sınırının bittiği noktada doğrudan `\` bulunması, sürecin benzer isimli başka bir klasörde değil, gerçekten o sistem dizininin içerisinde çalıştığını garanti eder.

Handle'ı işimiz biter bitmez kapatıyoruz, döngünün geri kalanına taşımıyoruz:

```c
CloseHandle(hProc);
```
Kodun tamamını isterseniz https://github.com/0xGently/Malware-Dev-Analysis-Library/blob/main/Enumeration/NtQuerySystemInformation/NtQuerySystemInformation.c adresinden bulabilirsiniz. Konumuz bu kadardı okuduğunuz için teşekkürler.