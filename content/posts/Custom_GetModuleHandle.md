---
tags:
  - obfuscation
title: Custom GetModuleHandle
date: 2026-10-25
draft:
author: 0xGently
---
## Giriş

Windows API'lerinin arka planda tam olarak nasıl çalıştığını incelemek Zararlı yazarken bize çok sayıda yeni teknik ve taktik kazandırır. Bu yazıda, en sık kullanılan API'lerden biri olan `GetModuleHandle` fonksiyonunu, hiçbir Windows API'si çağırmadan sıfırdan nasıl implemente edebileceğimizi inceleyeceğiz. Tabiki bunu yapma sebeplerimizden en büyüğü sürekli kullanmış olduğumuz bu fonksiyonu IAT(Import Address Table) içerisinden gizlemek. 

Bildiğiniz gibi `GetModuleHandle`, verdiğiniz bir DLL ismine karşılık o modülün bellekte yüklü olduğu base adresini döner. Yaptığı işlem aslında gayet nettir: OS loader tarafından her process için tutulan ve yüklü modülleri barındıran bir listeyi taramak. Bu liste, Process Environment Block (PEB) yapısının içinde yer alır. Bu yazının odak noktası da PEB'e manuel olarak ulaşıp bu listeyi nasıl parse edeceğimizi adım adım göstermek olacak.

Ancak PEB'i parse etmeye başlamadan önce yapıyı doğru anlamak gerekiyor. PEB'in içindeki bu modül verisi özünde bir linked list'tir. Dolayısıyla spesifik Windows yapılarına girmeden önce, OS loader'ın bu iş için neden basit bir array yerine linked list kullandığına kısaca değineceğiz. Bu temel mantık oturduğunda, PEB'deki verileri okumak karmaşık bir işlem olmaktan çıkıp, standart bir linked list üzerinde gezinmeye dönüşecek.

## Array'ler ve Linked List'ler

Verileri bellekte tutarken array'ler, yapıları gereği contiguous (bitişik) bellek bloklarıdır. Eleman boyutunu bildiğiniz sürece başlangıç adresine basit bir pointer aritmetiği uygulayarak herhangi bir indekse doğrudan erişebilirsiniz. Bu durum onları son derece hızlı ve cache-friendly yapar. Ancak array'lerin en büyük dezavantajı dinamik olarak genişletilmelerinin maliyetli olmasıdır. Ayrılan kapasite dolduğunda yeni bir eleman eklemek isterseniz, bellekte daha büyük yeni bir alan allocate etmeniz ve tüm mevcut veriyi bu yeni alana kopyalamanız gerekir.

Bir process'in yaşam döngüsü boyunca sürekli yeni DLL'ler yüklenebilir veya mevcutlar unload edilebilir. Boyutu sürekli değişen böyle dinamik bir modül listesi için array kullanmak, sürekli bellek kopyalama işlemi gerektireceğinden son derece verimsizdir.

Linked list'ler tam olarak bu sorunu çözer. Tek ve büyük bir bitişik bellek bloğu yerine, her eleman (node) için bağımsız allocation yapılır ve her eleman bir sonrakinin (veya öncekinin) bellek adresini bir pointer aracılığıyla tutar. Listeye yeni bir modül ekleneceğinde mevcut veriyi taşımaya gerek kalmaz; sadece yeni bir alan allocate edilip aradaki pointer bağlarının güncellenmesi yeterlidir.

Bunun teknik bedeli ise random access özelliğinin kaybolmasıdır; belirli bir elemana ulaşmak için listeyi baştan taramanız gerekir. Ancak OS loader'ın modül listesi senaryosunda belirli bir indekse doğrudan erişme ihtiyacı zaten yoktur. Yapılan işlem, aranan DLL ismine denk gelene kadar listeyi baştan sona taramaktır. İndeks bazlı erişime ihtiyaç duyulmadığı ve dinamik ekleme/çıkarma operasyonları sık olduğu için, Windows'un bu yapıda array yerine linked list kullanması en mantıklı mühendislik tercihidir.

## Çift Yönlü Linked List'ler

Tek yönlü linked list'lerde her node, sadece bir sonrakini işaret eden tek bir pointer barındırır. Eğer listede sadece tek bir yönde ilerleyecekseniz bu yapı yeterlidir. Ancak önemli bir dezavantajı vardır: Bulunduğunuz node'dan bir öncekine doğrudan dönemezsiniz. Geri gitmeniz gerektiğinde, listenin en başına dönüp ilgili node'a kadar tekrardan taramanız gerekir.

Çift yönlü linked list yapısı ise her node'a iki adet pointer ekleyerek bu kısıtlamayı tamamen ortadan kaldırır. Windows mimarisinde bu yapı `LIST_ENTRY` olarak adlandırılır. İçerisindeki pointer'lar ise ileri bağlantı için `Flink` (Forward Link) ve geri bağlantı için `Blink` (Backward Link) olarak isimlendirilir.

Windows'un bu yapıyı kodda nasıl tanımladığına adım adım bakalım. İlk olarak yapının tanımı ve bir sonraki elemanı gösteren pointer gelir.
```c
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink; // Bir sonraki node'un bellek adresini tutar
```

Hemen ardından geriye dönük pointer gelir ve yapı tamamlanır:
```c
    struct _LIST_ENTRY *Blink; // Bir önceki node'un bellek adresini tutar
} LIST_ENTRY, *PLIST_ENTRY;
```

Tüm yapı sadece bu iki pointer'dan ibarettir. Bu minimal tasarım sayesinde listeyi `Flink` üzerinden ileriye, `Blink` üzerinden geriye doğru tarayabilirsiniz. Sisteme sağladığı en büyük performans avantajı ise bir node'u O(1) karmaşıklığıyla (sabit sürede) silebilmenizdir. İlgili node zaten hem önceki hem de sonraki komşularının adresini bildiği için, listeyi baştan taramaya gerek kalmadan sadece pointer'ları güncelleyerek aradan çıkarılabilir.

`LIST_ENTRY` struct'ı yalnızca OS loader'ın modül listesinde değil, Windows kernel ve `ntdll` yapılarının neredeyse tamamında standart olarak kullanılan temel bir yapı taşıdır. Bu yapının mantığını kavradığınızda, Windows iç dünyasındaki veri yapılarının büyük bir kısmını da anlamış olursunuz.

## Circular List'ler ve List Head

Windows mimarisinde `LIST_ENTRY` yapısını incelerken akla gelen ilk teknik soru genellikle listenin sonunun nasıl tespit edileceğidir. Standart bir linked list tasarımında iterasyon şartı basittir: Son node'un ileri yönlü pointer'ı `NULL` değerini taşır ve döngü bu `NULL` değerine ulaşıldığında sonlanır.

Ancak Windows, çekirdek yapılarında `NULL` ile biten listeler yerine dairesel bir tasarım kullanır. Bu yapıda listenin son node'unun `Flink` pointer'ı `NULL`'a değil, tekrar en başa işaret eder. Benzer şekilde, ilk node'un `Blink` pointer'ı da listenin en sonuna bağlanır. Böylece yapı kendi üzerine kapanan bir halka halini alır. Tıpkı kendini yiyen bir yılan gibi.

![Logo](/assets/img/custom_getmodulehandle.png)

Bu dairesel yapının sonsuz bir döngüye dönüşmemesi için, referans alınabilecek sabit bir başlangıç noktasına ihtiyaç vardır. Windows terminolojisinde bu noktaya **List Head** denir. List head, özünde standart bir `LIST_ENTRY` değişkenidir ancak tek bir temel farkı vardır: Gerçek bir veriyi (örneğin yüklü bir modülü) temsil etmez. Sadece bir parent struct'ın (bizim senaryomuzda birazdan değineceğimiz `PEB_LDR_DATA` yapısının) içinde yer alan bir sabit referans noktası görevi görür. `Flink` ve `Blink` pointer'ları, listedeki ilk ve son "gerçek" veri node'larına işaret eder.

Bu mimari üzerinde bir listeyi taramak istediğimizde döngü mantığını nasıl kurduğumuza adım adım bakalım. İlk olarak başlangıç noktamızı, yani head'in gösterdiği ilk gerçek elemanı tanımlarız:
```c
PLIST_ENTRY current = head->Flink;
```

Döngümüz, standart listelerdeki gibi `NULL` değerini aramak yerine, okuduğumuz adresin tekrar başlangıç sabit referans noktasısına (head) dönüp dönmediğini kontrol eder:
```c
while (current != head) {
    // Node üzerindeki işlemler burada yapılır...
```

Döngü gövdesindeki işlemler bittikten sonra, bir sonraki node'a geçmek için yine `Flink` pointer'ı üzerinden ilerlenir:
```c
    current = current->Flink;
```

Bu tasarımının en büyük mühendislik avantajı, boş listeler için ekstra bir `if (current == NULL)` kontrolüne ihtiyaç bırakmamasıdır. Eğer liste tamamen boşsa, `head->Flink` pointer'ı doğrudan `head`'in kendisine işaret edecek ve `while` şartı baştan sağlanmadığı için döngüye hiç girilmeyecektir.

## PEB_LDR_DATA

Dairesel ve çift yönlü linked list mantığını oturttuğumuza göre, Windows'un yüklü modülleri takip etmek için arka planda kullandığı asıl yapıya geçebiliriz: `PEB_LDR_DATA`.

Yapının başlangıcında temel boyut ve durum bilgileri yer alır:
```c
typedef struct _PEB_LDR_DATA {
    ULONG   Length;
    BOOLEAN Initialized;
    HANDLE  SsHandle;
```

Hemen sonrasında ise modül listelerini barındıran üç adet `LIST_ENTRY` alanı gelir:
```c
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    // ... (kalan alanlar)
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

Dikkat ederseniz OS loader, modülleri tek bir liste yerine üç farklı sıralama (yükleme sırası, bellek adresi sırası ve başlatılma sırası) ile takip ediyor. Aslında üç liste de bellekteki aynı modül kayıtlarını birbirine bağlıyor; sadece her modülün içindeki farklı `Flink`/`Blink` çiftleri üzerinden rotalar değişiyor. Bizim `GetModuleHandle` implementasyonumuz için odaklanacağımız alan **`InMemoryOrderModuleList`** olacak.

Bir önceki bölümde bahsettiğimiz list head (sabit referans noktası) kavramı tam olarak buradaki `InMemoryOrderModuleList`'tir. Kendisi gerçek bir modül değildir. `Flink` pointer'ı ilk yüklenen modüle, `Blink` pointer'ı ise son yüklenen modüle işaret eder; bu sabit referans noktası üzerinden `Flink` yönünde ilerleyerek process'e yüklenmiş her DLL'e ulaşabiliriz.

Bu listedeki gerçek veri düğümleri ise `LDR_DATA_TABLE_ENTRY` adı verilen farklı bir struct'tır. Modülün bellekteki base adresini ve ismini asıl tutan yapı budur. Ancak burada çok kritik bir teknik detay devreye giriyor: Listeyi gezerken `Flink` üzerinden elde ettiğimiz pointer, doğrudan `LDR_DATA_TABLE_ENTRY` yapısının başlangıç adresini göstermez. Bize dönen adres, bu struct'ın biraz daha içine gömülü olan `LIST_ENTRY` alanının adresidir.

Gerçek modül verilerine (isim, base adres) ulaşmak için, bu içteki pointer'dan yola çıkarak struct'ın en başındaki adresi hesaplamamız gerekir. Kod yazma aşamasına geldiğimizde, bu bellek aritmetiğini C'deki `CONTAINING_RECORD` makrosunu kullanarak çözeceğiz.

## PEB'i TEB üzerinden Okumak

PEB yapısının içindeki modül listelerini nasıl gezeceğimizi inceledik, ancak en temel soruyu henüz yanıtlamadık: PEB'in bellek adresine (pointer) baştan nasıl ulaşacağız? Hiçbir Windows API'si kullanmama kuralımız gereği `GetModuleHandle` veya benzeri sistem çağrılarına başvuramayız. Bu nedenle doğrudan donanım seviyesindeki register'lara gitmemiz gerekiyor.

Windows'ta çalışan her thread'in kendisine ait bir Thread Environment Block (TEB) yapısı bulunur. Bu TEB, ait olduğu process'in genel PEB'ine işaret eden bir pointer barındırır. x64 mimarisindeki Windows sistemlerde işletim sistemi, o an çalışan thread'in TEB adresini `GS` segment register'ı üzerinden tutar. İşletim sistemine herhangi bir adres sormanıza gerek yoktur; thread çalıştığı sürece TEB'in adresi her zaman sabit olarak `GS:[0x30]` offsetinde bulunur. TEB'in içinden PEB pointer'ına gitmek için gereken offset ise `0x60`'tır. Kısacası, `GS:[0x60]` adresini okumak bize hiçbir API çağrısı olmadan doğrudan `PEB*` verir.

Ancak standart C sözdizimi, segmente dayalı bellek okumalarını tek başına ifade edemez. Bunun için kodu GCC/Clang derleyicilerine uygun inline assembly ile donanıma doğrudan söylememiz gerekiyor.

İlk olarak sadece x64 mimarisinde olduğumuzu garanti altına alıp dönüş değişkenimizi tanımlıyoruz:
```c
static PPEB GetPebManually(void)
{
#if defined(__x86_64__)
    PPEB peb;
```

Ardından inline assembly bloğumuzu başlatıyoruz. Burada kullanılan `__volatile__` anahtar kelimesi kritiktir; derleyiciye optimizasyon yaparken bu kodu es geçmemesini, sırasını değiştirmemesini ve kesinlikle çalıştırmasını söyler:
```c
    __asm__ __volatile__(
```

İşin kalbi olan CPU komutu tam olarak burasıdır. `movq` (move quadword) ile 64-bitlik bir veriyi okuyoruz. `%%gs:0x60` ifadesi, GS segment register'ına göre 0x60 offsetindeki adresten veriyi alır ve `%0` ile gösterilen ilk çıktı hedefine yazar. (GCC assembly sözdiziminde register'lar `%` ile belirtildiği için, inline assembly içinde `gs` yazarken kaçış karakteri olarak çift `%` kullanmamız gerekir):
```c
        "movq %%gs:0x60, %0"
```

Şimdi assembly dünyasındaki bu `%0` hedefinin, C dünyasındaki hangi değişkene karşılık geldiğini derleyiciye açıklamamız gerekiyor. `"=r"` ifadesindeki `=`, bunun sadece yazılabilir bir çıktı (write-only output) olduğunu belirtir. `r` ise derleyiciye bu kopyalama işlemi için uygun gördüğü herhangi bir general-purpose register'ı seçme özgürlüğü verir. Sonuç olarak okunan değer C tarafındaki `peb` değişkenine aktarılır:

```c
        : "=r" (peb)
    );
    return peb;
```

Eğer kod x64 mimarisinde derlenmiyorsa, hata verdirip bloğu kapatıyoruz:
```go
#else
    #error "x64 only (GS:[0x60])"
#endif
}
```
Bu kadar. Tek bir CPU instruction'ı yazarak, hiçbir Windows API'sine dokunmadan doğrudan PEB pointer'ını çekip aldık. Artık elde ettiğimiz bu pointer üzerinden modül listelerini taramayacağımız fonksiyona geçebiliriz.

## FindModuleBaseManually Function

İlk adımda fonksiyonumuzu tanımlıyor ve bir önceki bölümde yazdığımız inline assembly fonksiyonunu çağırarak PEB'in base adresini alıyoruz:
```c
PVOID FindModuleBaseManually(const wchar_t* targetModuleName)
{
    PPEB peb = GetPebManually();
```
Hemen ardından standart bir güvenlik kontrolü yapıyoruz. PEB'in kendisi veya içindeki `LDR_DATA` yapısı (modül listelerini tutan alan) herhangi bir sebeple başlatılmamışsa, programın çökmemesi için işlemi iptal edip `NULL` dönüyoruz:
```c
    if (!peb || !peb->Ldr) {
        return NULL;
    }
```
Artık modül listesinin kendisine ulaşabiliriz. Dairesel listeyi tarayabilmek için referans noktamız olan sabit referans noktasını (`head`) belirliyor ve döngüye başlayacağımız ilk "gerçek" elemanı `Flink` üzerinden seçiyoruz:
```c
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;
```
Bulduğumuz base adresini tutacağımız değişkeni tanımladıktan sonra, dairesel liste döngümüzü başlatıyoruz. Daha önce konuştuğumuz gibi, durma şartımız `NULL` değil, okuduğumuz adresin tekrar başlangıç sabit referans noktasısına (`head`) eşit olması:
```c
    PVOID foundBase = NULL;

    while (current != head)
    {
```
İşte geldik bütün sürecin en kritik matematiksel işlemine. `current` pointer'ımız, modül yapısının en başını değil, içine gömülü olan `LIST_ENTRY` alanını gösteriyor. `CONTAINING_RECORD` makrosunu kullanarak bu içteki offset'ten geriye doğru gidiyor ve asıl veri yapımız olan `LDR_DATA_TABLE_ENTRY_COMPLETE`'in başlangıç adresini hesaplıyoruz:
```c
        PLDR_DATA_TABLE_ENTRY_COMPLETE entry = CONTAINING_RECORD(
            current,
            LDR_DATA_TABLE_ENTRY_COMPLETE,
            InMemoryOrderLinks
        );
```

Asıl yapıya ulaştığımıza göre, modülün ismini okumaya başlayabiliriz. `BaseDllName` alanı genellikle bir `UNICODE_STRING` yapısıdır. Önce buffer'ın geçerli olup olmadığını kontrol ediyor, ardından karakter sayısını hesaplıyoruz (çünkü `Length` alanı karakter sayısını değil, byte cinsinden boyutu verir):

```c
        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0)
        {
            int charCount = entry->BaseDllName.Length / sizeof(WCHAR);
```

Arka planda neler olup bittiğini görmek için listeyi tararken bulduğumuz her DLL'i ve onun base adresini ekrana yazdırıyoruz:
```c
            wprintf(L"[Loaded Module] %-20.*s  (Base: 0x%p)\n",
                    charCount,
                    entry->BaseDllName.Buffer,
                    entry->DllBase);
```

Ve eşleşme kontrolü: Okuduğumuz modülün ismi, aradığımız modülün ismiyle (örneğin "kernel32.dll") eşleşiyor mu? Büyük/küçük harf duyarsız bir karşılaştırma (`_wcsnicmp`) yapıyoruz. Eğer eşleşirse, modülün base adresini (`DllBase`) kaydedip döngüden çıkıyoruz:
```c
            if (targetModuleName &&
                _wcsnicmp(entry->BaseDllName.Buffer, targetModuleName, charCount) == 0)
            {
                foundBase = entry->DllBase;
                break; 
            }
        }
```
Eğer bu modül aradığımız modül değilse, listeyi taramaya devam etmek için `Flink` üzerinden bir sonraki elemana geçiyoruz:
```c
        current = current->Flink;
    }
```

Son olarak, eğer döngü kırıldıysa bulduğumuz base adresini; eğer liste bittiyse ve eşleşme bulunamadıysa baştaki `NULL` değerini geri döndürüp fonksiyonu sonlandırıyoruz:
```c
    return foundBase;
}
```

Böylece `GetModuleHandle` API'sine hiç dokunmadan, işletim sisteminin kendi iç veri yapılarını manuel olarak tarayarak bir DLL'in bellek adresini tamamen kendi yöntemlerimizle elde etmiş olduk.

Konumuz bu kadardı biraz uzun sürmüş olabilir ama temel kavramları veya structları en fazla bu kadar kısa ve net anlatabildim. Konuda anlatılan kodun tamamına ulaşmak isterseniz [malware-development-library](https://github.com/0xGently/malware-development-library/tree/main/IAT-Hiding/GetModuleHandle) adresinden ulaşabilirsiniz.
