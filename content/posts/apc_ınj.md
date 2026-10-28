---
tags:
  - Execution
title: Local APC Injection
date: 2026-10-21
draft:
author: 0xGently
---

# Apc Injection

Günümüzde birtakım zararlılar yazma konusunda  payload'umuzu çalıştırmak için kullandığımız birçok teknik var. Bu yazıda, işletim sisteminin doğal işleyişini kendi lehimize kullandığımız, en temel ve etkili yöntemlerden biri olan **APC Injection** tekniğine odaklanacağız. İşin bellek ayırma  gibi her enjeksiyonda tekrarlanan standart kısımlarıyla vakit kaybetmeden doğrudan tekniğe odaklanacağız. 

## APC Nedir ? (Asynchronous Procedure Call)

En basit haliyle APC, belirli bir thread bağlamında asenkron olarak çalıştırılmak üzere sıraya alınmış bir fonksiyondur. Windows işletim sisteminde çalışan her thread'in kendine ait bir APC kuyruğu bulunur.

**Teknik olarak bu durum, işletim sistemi çekirdeğindeki thread nesnelerinin yapısıyla ilgilidir. Windows, her thread'i bellekte `_KTHREAD` adında bir struct olarak tutar. Bu struct'ın içerisinde, o thread'in sırayla işleyeceği görevleri gösteren gizli bir liste işaretçisi yer alır. Yani APC, doğrudan bu yapının yönettiği sistem mekanizmasının bir parçasıdır.**

Bunu, o thread'in "yapılacaklar listesi" olarak düşünebiliriz. Normal şartlarda, sistem veya diğer programlar hedef thread'e 'Eğer boş vaktin olursa şu fonksiyonu da aradan çıkar' diyerek bu listeye dışarıdan görev ekleyebilir. Bizim amacımız ise bu listeye zararlı kodumuzu gizlice eklemektir. 

## Queue Nedir ?

Yukarıda bahsettiğimiz "yapılacaklar listesi" aslında tamamen algoritmik bir veri yapısı olan Kuyruk (Queue) mantığıyla çalışır. Bilgisayar bilimindeki en temel yapılardan biri olan kuyruklar, FIFO (First In, First Out) yani "İlk Gelen İlk Çıkar" kuralına göre işler. Tıpkı bir banka veya ekmek kuyruğunda bekleyen insanlar gibi, thread'in listesine ilk eklenen görev, thread tarafından ilk olarak işleme alınır. İşletim sistemi görevlerin sırasını bu algoritmik yapı sayesinde hiç karıştırmadan yönetir.

## Alertable State Nedir ?

Burada kritik bir problemimiz var: Bir thread'in APC kuyruğuna görev eklemek, o görevin hemen çalışacağı anlamına gelmez. Thread, kendi ana işini bırakıp sizin eklediğiniz fonksiyona bakmaz.

Zararlı kodumuzun çalışması için, hedeflediğimiz thread'in "Alertable State" dediğimiz uyarılabilir bir bekleme durumuna geçmesi gerekir. Thread bu duruma geçtiğinde işletim sistemine şu mesajı verir: _"Ben şu an beklemeye geçiyorum. Eğer kuyruğumda bekleyen bir APC görevi varsa,onu çalıştırabilirim."_ İşte biz de tam olarak bu boşluktan faydalanacağız.

## Local APC Injection

Local APC Injection yaparken hedeflerimiz oldukça nettir. Başka bir process'in içine girmeye çalışmıyoruz; kendi oluşturduğumuz sürecin içindeki bir thread'i kullanacağız. Akışımız temel olarak şu şekilde ilerler:

1. Kendi sürecimiz içinde bir thread oluştururuz.
    
2. Zararlı kodumuzun adresini, bu thread'in APC kuyruğuna ekleriz.
        
3. Thread'i kasıtlı olarak "Alertable State" durumuna sokarız.
    
4. Thread beklemeye geçtiği an, kuyruktaki görevimizi fark eder ve shellcode'umuzu çalıştırır.

## QueueUserAPC Fonksiyonu

Zararlı kodumuzu thread'in yapılacaklar listesine eklemek için `QueueUserAPC` fonksiyonunu kullanıyoruz. Bu WinAPI'nin yapısı şu şekildedir:
```c
DWORD QueueUserAPC(
  [in] PAPCFUNC  pfnAPC,
  [in] HANDLE    hThread,
  [in] ULONG_PTR dwData
);
```

Bu üç parametreyi kısaca inceleyelim:

- **`pfnAPC`:** Çalıştırılacak olan fonksiyonun adresidir. Biz buraya, bellekte çalıştırılabilir olarak ayarladığımız shellcode'umuzun adresini vereceğiz.
        
- **`hThread`:** Hedef aldığımız thread'in handle değeridir. Bu görevi (payloadu) hangi thread'in kuyruğuna ekleyip çalıştıracağımızı buradan belirtiriz.
    
- **`dwData`:** Fonksiyonumuz ekstra bir parametreye ihtiyaç duyuyorsa buradan göndeririz. APC injection işlemlerinde shellcode çalıştırdığımız için genellikle bu değeri `NULL` olarak bırakırız.
    
    
Örnek kullanımımız mesela şu şekildedir:
```c
// Zararlı kod adresini hedef thread'in kuyruğuna ekliyoruz.
QueueUserAPC((PAPCFUNC)ShellcodeAddress, hThread, NULL);
```

Görevimizi kuyruğa ekledik, peki thread'i nasıl Alertable State'e sokacağız? Windows, bu iş için kullanabileceğimiz çeşitli bekleme fonksiyonları sunar. Bunların ortak özelliği, doğru parametreler verildiğinde thread'i uyarılabilir duruma sokmalarıdır.

Çoğu bekleme fonksiyonu, neyi beklediğini bilmek için bir obje handle'ına ihtiyaç duyar. Gerçek bir senaryoda bu obje başka bir thread tarafından tetiklenir ve bekleme biter. Ancak bizim tek amacımız thread'i sonsuza kadar beklemeye alıp aradan APC'mizi çıkartmak olduğu için, asla tetiklenmeyecek "sahte" bir event objesi yaratır ve onu bekletiriz.


Sahte objemizi şu şekilde tek satırda oluşturabiliriz:
```c
HANDLE hDummyEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
```

Şimdi bu thread'i Alertable State'e sokan birkaç fonksiyonun nasıl kullandığımızı inceleyelim:

### SleepEx

`SleepEx`, bir thread'i belirli bir süre boyunca askıya alan fonksiyondur. Ekstra bir objeye ihtiyaç duymaz, bu yüzden kullanımı en kolay olanıdır. İkinci parametresi `bAlertable`'dır ve `TRUE` yapıldığında thread uyarılabilir duruma geçer.
```c
// Thread'i sonsuza dek uyutur ve Alertable duruma sokar.
SleepEx(INFINITE, TRUE);
```

Thread sonsuz (`INFINITE`) uykuya dalar, ancak Alertable olduğu için bizim APC'miz geldiğinde hemen kodumuzu çalıştırır.

### WaitForSingleObjectEx

Sadece belirli bir objenin (bizim durumumuzda asla tetiklenmeyecek sahte event'in) durumunu bekleyen fonksiyondur. Üçüncü parametresi Alertable durumunu belirler.
```c
// Sahte event objesinin tetiklenmesini sonsuza kadar uyarılabilir şekilde bekle.
WaitForSingleObjectEx(hDummyEvent, INFINITE, TRUE);
```

Event hiçbir zaman sinyal almayacağı için bekleme asla normal yollarla bitmez, ancak APC kuyruğu devreye girdiğinde kodumuz aradan fırlar.
### WaitForMultipleObjectsEx

Bir önceki fonksiyonun array versiyonudur. Tek bir obje yerine, birden fazla objeyi aynı anda beklemek için kullanılır. Biz yine kendi sahte objemizi bir dizi içine koyarak bu fonksiyonu istismar edebiliriz.
```c
// Obje dizisini bekle, son parametre TRUE ile Alertable moda geç.
HANDLE eventArray[] = { hDummyEvent };
WaitForMultipleObjectsEx(1, eventArray, FALSE, INFINITE, TRUE);
```
### MsgWaitForMultipleObjectsEx

Bu fonksiyon, normal obje bekleme işlemine ek olarak thread'in mesaj kuyruğundaki input event'leri bekleyebilir. Genellikle GUI thread'lerinde kullanılır ama biz yine kendi manipülasyonumuz için kullanacağız. Alertable yapmak için `MWMO_ALERTABLE` bayrağını kullanırız.
```c
// Hem sahte objeyi bekle hem de uyarılabilir duruma geç.
MsgWaitForMultipleObjectsEx(1, &hDummyEvent, INFINITE, QS_ALLINPUT, MWMO_ALERTABLE);
```
### SignalObjectAndWait

Bu API, önce bir objeyi tetikler, hemen ardından başka bir objeyi beklemeye başlar. Parametrelerin sonunda yine `bAlertable` bayrağı bulunur. Biz bunu kullanırken yine kendi yarattığımız sahte objeleri hedef gösterebiliriz.

```c
// İlk event'i sinyalle, ikinci (sahte) event'i uyarılabilir şekilde bekle.
SignalObjectAndWait(hSignalEvent, hDummyEvent, INFINITE, TRUE);
```

İşte hepsi bu kadar. Özetle, önce `QueueUserAPC` ile zararlı kodumuzu thread'in cebine koyuyoruz, ardından yukarıdaki fonksiyonlardan birini kullanarak thread'i o kodlara bakmaya zorluyoruz. Gördüğünüz gibi, Local APC Injection aslında bir thread'in zamanlama mekanizmalarını kendi lehimize kullanmaktan ibaret şık bir tekniktir.

**NOT:** Bu teknikle ilgili PoC kodunun tamamına erişmek isterseniz, GitHub hesabımdaki [malware-development-library](https://github.com/0xGently/Malware-Dev-Analysis-Library/tree/main/Injection/Apc-Injection) adlı repoya göz atabilirsiniz.