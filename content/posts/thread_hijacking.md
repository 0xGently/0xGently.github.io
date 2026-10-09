---
title: Thread_Hijacking
tags:
  - Execution
date: 2026-10-09
draft:
author: 0xGently
---
## Remote_Thread_Creation

Bu yazımızda; meşru bir procesesi askıya alıp, bellek alanına shellcode enjekte ettikten sonra mevcut thread'in  RIP/EIP registerlarını manipüle ederek çalışan bir teknikten bahsedeceğim.

Siber güvenlik dünyasında, hedef bir proses içerisinde kod çalıştırmak için genellikle `CreateRemoteThread` gibi API'ler tercih edilir. Ancak bu fonksiyonlar güvenlik mekanizmaları (AV/EDR) tarafından çok sıkı izlenir ve anında engellenir. Thread Hijacking ise sıfırdan yeni ve şüpheli bir thread oluşturmak yerine, halihazırda var olan meşru bir thread'in rotasını "çalmayı" hedefler. 

Geliştireceğimiz senaryoda ilk olarak `CREATE_SUSPENDED` bayrağı ile kurban bir Windows procesi (örneğin System32 altındaki bir araç) başlatacağız. Ardından, hedef procesin bellek alanında yer ayırıp zararlı shellcode'umuzu bu bölgeye enjekte edeceğiz. 

 Sonraki aşamada ise `GetThreadContext` ve `SetThreadContext` API'lerini kullanarak işlemcinin bir sonraki çalıştıracağı komut adresini tutan `RIP` veya `EIP` register'ının adresini hedef process üzerinde yer ayırıp yazdığımız zararlının olduğu adres ile değiştireceğiz

Son olarak `ResumeThread` ile thread'i uyandırdığımızda, işletim sistemi hiçbir şeyden şüphelenmeden bizim kodumuzu devam ettirecektir. Konuyu `part 1-2-3` olarak ele alacağım. Kodun tamamından ziyade part `1-2-3` içerisinde kullandığım fonksiyonları zincir sırasınca anlatacağım.
### Part 1 

Kodumuzun ilk kısmında, hedef process'i duraklatılmış (suspended) bir şekilde başlatacak olan ana fonksiyonumuzu tanımlıyoruz:
```c
BOOL StartSuspendedProcess(const char* exeName,
                           DWORD* outPid,
                           HANDLE* outProcess,
                           HANDLE* outThread)
```

Bu fonksiyon bizden hedeflediğimiz uygulamanın adını (`exeName`, örneğin "notepad.exe") istiyor. İşlemini başarıyla tamamladığında ise, oluşturduğu yeni process'in PID değerini, process handle'ını ve main thread handle'ını verdiğimiz pointer'lar üzerinden bize geri verecek.

Şimdi fonksiyonun içerisine girip adım adım neler olduğuna bakalım:
```c
    if (!GetSystemDirectoryA(path, MAX_PATH)) {
        printf("Oops! GetSystemDirectoryA failed. ^_^: %lu\n", GetLastError());
        return FALSE;
    }
```

Burada kullandığımız API'nin adı `GetSystemDirectoryA`. Amacı, Windows'un System32 dizininin (genellikle `C:\Windows\System32`) bulunduğu konumu bulup `path` buffer'ına yazmaktır. Yolu doğrudan kodun içine hardcoded (elle) yazmak yerine bu API'yi kullanmak çok daha sağlıklıdır; çünkü Windows her zaman C sürücüsünde kurulu olmayabilir. Eğer bir şeyler ters giderse, `GetLastError()` ile Windows'un bize döndürdüğü hata numarasını alıp ekrana basıyoruz ve fonksiyonu sonlandırıyoruz.

```c
    // C:\Windows\System32\<exeName>
    if (!PathAppendA(path, exeName)) {
        printf("Oops! PathAppendA failed. ^_^:\n");
        return FALSE;
    }
```

Sırada `PathAppendA` fonksiyonu var. Bu fonksiyonun görevi oldukça basittir: Az önce elde ettiğimiz System32 dizini ile parametre olarak aldığımız dosya adını güvenli bir şekilde birleştirmek. İşlem bittiğinde elimizde temiz bir tam yol (örneğin `C:\Windows\System32\notepad.exe`) oluyor.


Sürecin asıl başlatıldığı nokta ise burası:  
```c
    if (!CreateProcessA(NULL, path, NULL, NULL, FALSE,
                        CREATE_SUSPENDED,  
                        NULL, NULL, &si, &pi))
    {
        printf("Oops! CreateProcessA failed. ^_^: %lu\n", GetLastError());
        return FALSE;
    }
```

Burada `CreateProcessA` API'sini kullanarak hedef programı başlatıyoruz. Aldığı birçok parametre var ancak bizim için en kritik olanı `CREATE_SUSPENDED` bayrağıdır (flag).

Bu parametreyi verme amacımız şudur: Process oluşturulur, gerekli bellek alanları ayrılır ancak main thread kodları çalıştırmaya başlamadan (entry point'e girmeden) anında duraklatılır (suspend). Bu bize büyük bir avantaj sağlar; process meşru bir şekilde ayağa kalkmıştır ama henüz çalışmaya başlamadığı için içine kendi zararlı kodumuzu enjekte edebileceğimiz geniş bir zaman penceremiz olur. Fonksiyon başarılı olduğunda, ihtiyacımız olan PID ve handle bilgileri `pi` (PROCESS_INFORMATION) yapısına yazılır ve kullanıma hazır hale gelir.

Buraya kadar tekniğin ilk aşamasını bitirdik. Zincirleme ise basitti:
1. Kullanıcıdan gerekli bilgileri al
2. Sistemdeki System32 dizininin gerçek yolunu bul  
3. Bunu kullanıcının vermiş olduğu program adı ile birleştir
4. En son gerekli bilgileri kullanarak `CREATE_SUSPENDED` bayrağı ile o programı başlat.

### Part 2
Hedef process'i duraklatılmış (suspended) bir şekilde başarıyla başlattığımıza göre, sıra geldi kendi zararlımızı bu uygulamanın belleğine gizlice yazmaya.

Bu işlem için yazdığımız özel fonksiyonun başlangıcına bir bakalım:
```c
BOOL WriteCodeToRemoteProcess(HANDLE hTarget,
                              unsigned char* code,
                              size_t codeSize,
                              void** outRemoteAddr)
```

Bu adımda kullanacağımız ana fonksiyonumuzun adı `WriteCodeToRemoteProcess`. Fonksiyon bizden; hedef process'in handle'ını (`hTarget`), enjekte edeceğimiz zararlı kodun bellekteki konumunu (`code`) ve bu kodun boyutunu (`codeSize`) istiyor. İşlem bittiğinde ise, kodun karşı process'in belleğinde tam olarak hangi adrese yazıldığını `outRemoteAddr` pointer'ı üzerinden bize geri verecek. Amacımız, kodu sorunsuz ve güvenli bir şekilde hedef hafızaya yerleştirmek.

Öncelikle hedef process içerisinden bir yer ayırıyoruz.
```c
    remoteBase = VirtualAllocEx(hTarget, NULL, codeSize,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE);
```

Burada kullandığımız API'nin adı `VirtualAllocEx`. Görevi, başka bir process (`hTarget`) içerisinde istediğimiz boyutta (`codeSize`) bir bellek alanı tahsis etmektir.

İkinci parametreyi `NULL` olarak veriyoruz, çünkü belleğin neresinden yer tahsis edileceğini işletim sisteminin kendisine bırakıyoruz. `MEM_COMMIT | MEM_RESERVE` parametreleri, bellekteki o alanı hem rezerve ettiğimizi hem de fiziksel olarak kullanıma açtığımızı belirtir. `PAGE_READWRITE` ise buranın sadece okunabilir ve yazılabilir olduğunu söylüyor. Dikkat ederseniz şimdilik "çalıştırma" (execute) yetkisi vermedik, çünkü kodu henüz belleğe yazmadık. Bu, EDR'ların dikkatini çekmemek için iyi bir pratiktir.

Yerimizi ayırdık, şimdi kodumuzu o alana kopyalama vakti:
```c
    if (!WriteProcessMemory(hTarget, remoteBase, code, codeSize,
                            &bytesWritten) || bytesWritten != codeSize) {
        printf("Oops! WriteProcessMemory failed. ^_^: %lu\n", GetLastError());
        return FALSE;
    }
```

`WriteProcessMemory` API'si, kendi belleğimizdeki kodu (`code`), hedef process'te az önce ayırdığımız o boş adrese (`remoteBase`) yazar. Fonksiyon başarılı olursa, karşıya kaç byte veri yazdığını `bytesWritten` değişkenine kaydeder.

Buradaki `if` bloğunda sadece fonksiyonun hata verip vermediğini kontrol etmiyoruz; aynı zamanda karşıya yazılan byte sayısının, bizim kodumuzun orijinal boyutuyla birebir eşleşip eşleşmediğine (`bytesWritten != codeSize`) bakıyoruz. Eğer eksik yazıldıysa veya fonksiyon patlarsa, hatayı ekrana basıp işlemi iptal ediyoruz.

Kodu karşı process'e başarıyla yazdık. Artık kendi tarafımızdaki koda ihtiyacımız yok:
```c
    SecureZeroMemory(code, codeSize);
```

Bu tek satırlık fonksiyon operasyonel güvenlik (OPSEC) açısından inanılmaz kritiktir. Kodu hedef process'e aktardıktan sonra, kendi process'imizin belleğinde kalan orijinal kopyayı sıfırlarla doldurarak yok ediyoruz. Böylece, sonradan belleğimizi tarayan bir antivirüs veya analist, bizim tarafımızda şüpheli bir payload kalıntısı bulamaz.

Şimdi ise hedef process içerisinde ayırdığımız alanın yetkilerini değiştiriyoruz
```c
    if (!VirtualProtectEx(hTarget, remoteBase, codeSize,
                          PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Oops! VirtualProtectEx failed. ^_^: %lu\n", GetLastError());
        return FALSE;
    } 
```

Hatırlarsanız, `VirtualAllocEx` ile hafızada yer ayırırken o alana sadece okuma ve yazma (`PAGE_READWRITE`) izni vermiştik. Windows'un güvenlik mekanizmaları (DEP - Data Execution Prevention), üzerinde çalıştırma yetkisi olmayan bellek alanlarındaki kodların çalışmasını engeller.

Bu yüzden `VirtualProtectEx` API'sini kullanarak hedef process'e tekrar müdahale ediyoruz ve kodumuzu yazdığımız o bellek alanının izinlerini `PAGE_EXECUTE_READWRITE` (Okuma, Yazma ve Çalıştırma) olarak güncelliyoruz. İzinler sorunsuz değişmezse hata verip çıkıyoruz. Bu adımı da geçtikten sonra, kodumuz hedef process içinde çalıştırılmaya tamamen hazır hale geliyor.

Buraya kadar ise yaptıklarımız şunlardı:
1. Kendi ana fonksiyonumuz ile kullanıcıdan gerekli bilgileri al.
2. `VirtualAllocEx` ile hedef process içerisinde yer ayır. 
3. `WriteProcessMemory` ile zararlıyı yaz.
4. `SecureZeroMemory` ile önceden yazmış olduğumuz zararlıyı temizle. 
5. `VirtualProtectEx` ile hedef processteki o alanın izinlerini değiştir.

### Part 3
Şimdi sıra geldi hedef processteki mevcut Threadın RIP registerında gösterdiği adresi kendi zararlımızın bellekteki adresine çevirmeye. İşte `RedirectThreadExecution` fonksiyonu tam olarak bu işi; yani thread'in mevcut akışını bozup ona "kendi işini bırak, git benim gösterdiğim adresteki kodu çalıştır" demeyi sağlıyor.

Adım adım kodun içine girelim:
```c
BOOL RedirectThreadExecution(HANDLE hTargetThread, void* remoteCodeAddr)
{
    CONTEXT ctx = { .ContextFlags = CONTEXT_CONTROL };
```

Fonksiyona dışarıdan hedef thread'in handle'ını (`hTargetThread`) ve çalışmasını istediğimiz kodun bellek adresini (`remoteCodeAddr`) veriyoruz.

Burada ilk olarak `CONTEXT` adında bir yapı (struct) tanımlıyoruz. Windows'ta bir thread duraklatıldığında, o anki CPU register'larının durumu bu yapıda tutulur. `.ContextFlags = CONTEXT_CONTROL` diyerek işletim sistemine şunu söylüyoruz: "Ben bu thread'in tüm register'larıyla ilgilenmiyorum, bana sadece kontrol register'larını (Instruction Pointer vb.) ver." Bu, hem performansı artırır hem de gereksiz verilerle uğraşmamızı engeller.

```c
    if (!GetThreadContext(hTargetThread, &ctx)) {
        printf("Oops! GetThreadContext failed. ^_^: %lu\n", GetLastError());
        return FALSE;
    }
```

Sıradaki API'miz `GetThreadContext`. Bu fonksiyon, duraklatılmış olan hedef thread'in mevcut durumunu (register değerlerini) alır ve az önce oluşturduğumuz boş `ctx` yapısının içine doldurur. Thread'in rotasını değiştirmeden önce  mevcut durumunun bir fotoğrafını çekiyoruz diyebiliriz. Eğer bu okuma işlemi başarısız olursa hata basıp çıkıyoruz.

İşin kalbinin attığı ve asıl manipülasyonun yapıldığı yer ise burası:
```c
#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteCodeAddr;
#elif defined(_WIN32)
    ctx.Eip = (DWORD)(ULONG_PTR)remoteCodeAddr;
#else
#error "Unsupported architecture"
#endif
```

Bir CPU'da bir sonraki çalıştırılacak olan komutun bellek adresini tutan çok özel bir register vardır. Bu, 64-bit sistemlerde `RIP` (Instruction Pointer), 32-bit sistemlerde ise `EIP` olarak adlandırılır.

Biz burada, `GetThreadContext` ile içini doldurduğumuz `ctx` yapısındaki `Rip` veya `Eip` değerini tamamen eziyoruz. Yerine de kendi zararlı kodumuzun bulunduğu bellek adresini (`remoteCodeAddr`) yazıyoruz. İçerideki `#ifdef` blokları ise kodun derlendiği mimariye (32-bit veya 64-bit) göre doğru register'ın seçilmesini garantiliyor.
```c
    if (!SetThreadContext(hTargetThread, &ctx)) {
        printf("Oops! SetThreadContext failed. ^_^: %lu\n", GetLastError());
        return FALSE;
    }
}
```

Son vuruş: `GetThreadContext` ile okuduk, `ctx.Rip` ile hedef adresi kendi kodumuzla değiştirdik. Şimdi bu manipüle edilmiş, üzerinde oynanmış yapıyı tekrar thread'e geri yüklememiz gerekiyor. `SetThreadContext` tam olarak bunu yapar.

Bu API başarılı olduğunda, thread'in beynindeki "bir sonraki çalıştırılacak komut" adresi artık bizim payload'umuzun adresidir. Artık tek yapmamız gereken bu duraklatılmış thread'i (`ResumeThread` ile) uyandırmak. Thread uyandığı saniye, orijinal programın entry point'ine gitmek yerine doğrudan bizim gösterdiğimiz adresten çalışmaya başlayacaktır.

Artık son zincir ise bu şekilde son buluyor:
1. `GetThreadContext` ile Thread ın o anki içini kaydet.
2.  `#ifdef` blokları ile 32-bit mi 64-bit mi diye kontrol et.
3. `SetThreadContext` ile düzenlenmiş Threadi geri yükle . 

Görüldüğü üzere bu konu aslında kendi shellcode/payload'ımızı (artık ne isim verirseniz) nasıl çalıştırabiliriz ? diye bize ekstra bir yöntem sunuyor. Bu işlemi tamamen bu şekilde hayal etmek yerine daha da farklılaştırıp bambaşka şekilde de kendi kodumuzu çalıştırabiliriz diye düşünmek faydalı. Zira bu metin boyunca sadece bir yöntem değil aslında bir zararlı yazılım kendi sınırları dışına çıkıp neler yapabilir ? bunlarıda görmüş olduk.
