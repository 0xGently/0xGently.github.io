---
tags:
  - enumeration
title: Thread_and_Process_Enumeration
date: 2026-10-17
draft: false
author: 0xGently
---


Bu yazımızda **`CreateToolhelp32Snapshot`** fonksiyonunu kullanarak nasıl process'ler veya
thread'ler hakkında bilgi toplarız onu anlatacağım.

Geliştirdiğimiz araçlarda veya yazdığımız zararlılarda hedef aldığımız bir **process**'e müdahale etmek istiyorsak, öncelikle sistemde o **process**'in nerede durduğunu tam olarak tespit etmemiz gerekiyor. 
Operasyonumuzu iki temel aşamaya böleceğiz. 
İlk olarak, elimizdeki düz bir metinden (örneğin `notepad.exe` gibi bir **process** isminden) yola çıkarak sistemdeki tüm **process**'leri tarayacak ve hedefimizin benzersiz kimlik numarasını, yani **PID**'sini çekeceğiz. İkinci aşamada ise elde ettiğimiz bu **PID** üzerinden hedef **process**'in içerisine girip, üzerinde manipülasyon yapabileceğimiz ya da ele geçirebileceğimiz geçerli bir **thread** yakalayacağız.

Kısacası bu bölümde; sistemdeki **process**'leri ve **thread**'leri en temel API'lerle nasıl **enumerate** edeceğimizi, bunları yaparken de işletim sisteminden ihtiyacımız olan **handle**'ları nasıl alacağımızı  kodlar üzerinden pratik bir şekilde göreceğiz.

**NOT:** Konuda bahsedilen fonksiyonların tamamına ulaşmak isterseniz https://github.com/0xGently/Malware-Dev-Analysis-Library/tree/main/Enumeration/CreateToolhelp32Snapshot adresinden bulabilirsiniz.

### Adım 1: Process Enumeration via function

İlk olarak sistemde çalışan process'ler arasından aradığımız hedefin PID'sini ve Handle'ını nasıl alacağımıza bakacağız. Kodu adım adım inceleyip işin arka planında neler döndüğünü anlayalım.

İlk hamlemiz, sistemdeki tüm process'lerin o anki listesini elde etmek:


```c
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
```
Burada `CreateToolhelp32Snapshot` API'sini kullanarak sistemin anlık bir görüntüsünü alıyoruz. Eğer güvenlik veya başka bir sebeple bu listeyi alamazsak, fonksiyon zaten en baştan `FALSE` dönüp işlemi iptal ediyor.

Daha sonra, bu liste içerisinde gezinirken verileri tutacağımız struct'ı ayağa kaldırıyoruz:
```c
PROCESSENTRY32W stEntry = { 0 };
stEntry.dwSize = sizeof(PROCESSENTRY32W);
```

Burada `PROCESSENTRY32W` yapısını oluşturduk ve içini sıfırladık. Alt satırdaki `dwSize` ataması ise kritik bir detaydır. Windows API'leri ile çalışırken ilgili struct'ın bellekteki boyutunu API'ye bildirmemiz gerekir, aksi takdirde fonksiyonlar genellikle hata verir.

Sıra geldi döngüye girip listedeki isimleri bizim aradığımız hedefle karşılaştırmaya:
```c
if (lstrcmpiW(stEntry.szExeFile, wszTargetName) == 0) {
    *pdwPid = stEntry.th32ProcessID;
```

Döngü her döndüğünde, o anki process'in adını (`szExeFile`) bizim verdiğimiz isimle (`wszTargetName`) kıyaslıyoruz. Eğer eşleşme bulursak, hedefin ID'sini (`th32ProcessID`) fonksiyonu çağırdığımız yere iletmek üzere pointer'a yazıyoruz.

```c
*phTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, stEntry.th32ProcessID);
if (*phTarget == NULL) {
    break;
}
```
Hedefi bulduktan sonra `OpenProcess` API'sini kullanarak süreç üzerinde tam yetki (`PROCESS_ALL_ACCESS`) talep ediyoruz. Eğer hedef süreç başarıyla açılırsa, ihtiyacımız olan handle'lı almış oluruz.

Burada kritik bir kontrolümüz var: Eğer yetki eksikliği veya sistem korumaları nedeniyle süreç açılamazsa (`NULL` dönerse), `break` ifadesiyle döngüyü sonlandırıyoruz. Normalde bir sistemde aynı isimde ama farklı `PID`'lerde birden fazla süreç (mesela Chrome sekmeleri) bulunabilir. Gelişmiş senaryolarda ilk süreç başarısız olduğunda `continue` ile diğer aynı isimli süreçleri denemek daha doğru bir yaklaşımdır. Ancak bu eğitim yazısında konuyu basitleştirmek ve akışı sade tutmak adına, ismi eşleşen ilk süreçte başarısız olursak aramayı kesmeyi (`break`) tercih ediyoruz.

_Not: Gerçek senaryolarda `PROCESS_ALL_ACCESS` gibi tam yetki istemek yerine, sadece yapacağınız işleme özel izinleri (örneğin sadece okuma/yazma izinlerini) talep etmek hem güvenlik duvarlarına takılmamak hem de gizlilik açısından her zaman daha doğru bir yaklaşımdır._

Son olarak, işimizi bitirdiğimizde açık kalan değerleri temizlememiz gerekiyor:
```c
CloseHandle(hSnapshot);
```

Memory leak yaşamamak adına, en başta aldığımız snapshot handle'ını kapatarak işletim sistemine kaynağı iade ediyoruz ve işlemi tamamlıyoruz.

### Adım 2: Thread Enumeration via function

Hedef process'i başarıyla bulduğumuza göre, şimdi sıra o process'in içinde çalışan bir thread'i  yakalamakta. 

Öncelikle, ufak bir güvenlik önlemiyle yola çıkıyoruz:
```c
if (pdwTid) *pdwTid = 0;
if (phThread) *phThread = NULL;
```

Bize dışarıdan parametre olarak gelen pointer'ların içini temizliyoruz. Eğer bu değişkenlerin içinde daha önceden kalma çöp değerler varsa, ileride başımızı ağrıtmasın diye baştan sıfırlamak her zaman iyi bir pratiktir.

Ardından, ilk fonksiyonda yaptığımıza benzer bir şekilde sistemin anlık görüntüsünü alıyoruz:
```c
hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
stEntry.dwSize = sizeof(THREADENTRY32);
```

Bu sefer `TH32CS_SNAPPROCESS` yerine `TH32CS_SNAPTHREAD` flag'ini kullanıyoruz. Çünkü amacımız process'leri değil, sistemde o an aktif olan tüm thread'leri listelemek. API'nin sorunsuz çalışması için `THREADENTRY32` struct boyutunu girmeyi yine unutmuyoruz.

  Sistemdeki **tüm** thread'ler elimizde. Şimdi bizim process'e ait olanı almamız lazım:
```c
if (stEntry.th32OwnerProcessID == dwProcessId) {
    *pdwTid = stEntry.th32ThreadID;
```

Buradaki mantık basit: Döngüyle tüm thread'leri geziyoruz ve "Bu thread'in sahibi olan process ID (`th32OwnerProcessID`), bizim aradığımız `dwProcessId` ile aynı mı?" diye soruyoruz. Eşleşme sağlandığında, thread'in kendi ID'sini (`th32ThreadID`) dışarı aktarmak üzere pointer'a yazıyoruz.

Sıra geldi bu thread'i açıp kontrolü elimize almaya:

```c
*phThread = OpenThread( THREAD_ALL_ACCESS, FALSE, stEntry.th32ThreadID);
```
Yine burada yukarıda kullandığımız fonksiyonun neredeyse aynısını kullanıyoruz. `PROCESS_ALL_ACCESS` gibi tam yetki istemek yerine, sadece yapacağınız işleme özel izinleri talep etmek yine çok daha iyidir. Biz şuanlık bu şekilde bırakıyoruz.

Ve son olarak, az önce çözdüğümüz o kritik hata kontrolü noktası:
```c
if (*phThread == NULL) {
    CloseHandle(hSnapshot);
    return FALSE;
}
```

Eğer `OpenThread` başarısız olursa (yetki eksikliği vs.), sessizce çıkıp gitmiyoruz. Sistemde asılı kalacak bir handle bırakmamak için (leak'lere sebep olmaması için) `CloseHandle(hSnapshot)` diyerek dükkanı temiz bir şekilde kapatıyor ve başarısız olduğumuzu (`FALSE`) bildiriyoruz. (Dikkat edin, ilk thread'de yetki alamazsak direkt `FALSE` dönüyoruz. Eğer process'in diğer thread'lerini denemek isterseniz, önceki fonksiyonda dediğimiz gibi burada da `return FALSE` yerine `continue` mantığı kurabilirsiniz.)

Toparlamak gerekirse; bu iki temel fonksiyonla sistemin arka planına inip hedef process ve thread'leri nasıl güvenli bir şekilde alacağınızı adım adım inceledik. İşletim sistemi seviyesinde çalışırken sadece ihtiyacımız olan yetkileri istemek ve işimiz bitince açık kalan handle'ları temizlemek, güvenli kodlamanın esaslarındandır.
