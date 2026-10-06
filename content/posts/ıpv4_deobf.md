---
title: "IPv4/IPv6 DeObfuscation"
date: 2026-04-10
draft: false
---
## IPv4/v6 DeObfuscation

Bu yazıda, dışarıdan bakıldığında son derece sıradan görünen bir ağ yapılandırma fonksiyonunun, nasıl bir shellcode decoder'a dönüştürüldüğünü inceleyeceğiz. Amacımız, saldıran tarafın zihniyetini anlayarak savunma sistemlerimizi bu tür "normal görünen anormallikleri" yakalayacak şekilde kurgulamak.

**Not**: Bu metinde anlattığım kodun tamamını https://github.com/0xGently/Malware-Dev-Analysis-Library/blob/main/Payload-Encryption-and-Obfuscation/06-IPv4_IPv6_DeObf/Deobfuscat%C4%B1on.c adresinde bulabilirsiniz. Ayrıca bu konunun mantığını oturtup kodun tam halini incelediğinizde diğer tekniklere uygulanan DeObfuscation işlemlerinide oluşturabilirsiniz. Zaten hemen hemen aynı ya sadece birkaç değişiklik yapmanız gerekmektedir o kadar.

Bu tekniğin merkezinde `ntdll.dll` içerisinde yer alan `RtlIpv4StringToAddressA` fonksiyonu bulunuyor. Microsoft'un resmi dokümantasyonuna baktığınızda bu fonksiyonun oldukça basit ve tek bir amacı olduğunu görürsünüz: `"192.168.1.1"` gibi metin tabanlı (string) bir IPv4 adresini almak ve bunu ağ soketlerinde kullanılabilmesi için 4 byte'lık ikili (binary) bir `struct in_addr` yapısına dönüştürmek.

Bizler ise bu fonksiyonu bir ağ yapılandırma aracı olarak değil ,parametre olarak düz metin kabul eden ve geriye 4 byte'lık saf makine kodu (hex) üreten, sistemin kalbine yerleştirilmiş hazır bir "decoder" fonksiyonu olarak göreceğiz.
  
```c
NTSTATUS status = pRtlIpv4ToAddr(ObfuscatedIpv4Array[i], FALSE, &pszTerminator, pCurrentWritePos);
```

Buradaki en kritik nokta, 4. parametre olan `pCurrentWritePos` değişkenidir. API, normal şartlar altında dönüştürdüğü veriyi yazmak için bir `struct in_addr*` pointer'ı bekler. Ancak biz buraya kendi tahsis ettiğimiz bir `PBYTE` (byte array pointer) veriyoruz.

Yazılım dünyasında bu kavrama **Type-Punning** denir. C ve C++ dillerinde işletim sistemi, çalışma zamanında (runtime) sizin verdiğiniz pointer'ın "tipini" pek umursamaz; sadece o pointer'ın işaret ettiği bellek adresine odaklanır. API, o adrese masum bir ağ konfigürasyonu yazdığını zannederken, biz aslında IP adresi kılığına sokulmuş 4 byte'lık shellcode parçamızı doğrudan kendi buffer'ımıza yazdırıyoruz.
```c
if (status != 0x00000000) 
{ 
    HeapFree(GetProcessHeap(), 0, pDecodedBuffer);
    return NULL;
}
```
API herhangi bir sebeple başarısız olursa (örneğin dizideki IP stringi hatalı formattaysa), kod doğrudan panikleyip çıkış yapmıyor. Önce `HeapFree` ile tahsis ettiği belleği sisteme iade ediyor. Unutmayın; bellek sızıntıları (memory leaks) süreçlerin kararsız çalışmasına neden olur ve modern EDR'ların davranışsal analiz (behavioral analysis) radarları bu tür kararsızlıklara karşı oldukça hassastır.

```c
pCurrentWritePos += 4;
```

Döngünün her iterasyonunda, hedef pointer tam olarak 4 byte ileri kaydırılıyor. Çünkü her bir IPv4 adresi matematiksel olarak 32-bit'lik (4 byte) bir veri bloğudur. Uygulanan bu basit pointer aritmetiği sayesinde, kodun içinde birbirinden bağımsız birer metin gibi duran onlarca IP adresi, bellekte ardışık ve bütünsel bir shellcode'a dönüşmüş oluyor.

Shellcode belleğe başarıyla yazıldıktan sonra burada bir hizalama problemi devreye girer.

Sizin asıl payload'unuz —örneğin bir Cobalt Strike beacon'ı, bir reverse shell veya özel bir implant— her zaman 4'ün tam katı uzunluğunda olmayacaktır. Diyelim ki 201 byte'lık bir payload'unuz var. Bunu 4 byte'lık IP bloklarına bölmek isterseniz, son bloğun eksik kalmaması için sonuna 3 byte'lık bir  padding eklenmesi gerekir. Payload'u hazırlayan araçlar bunu genellikle kriptografide çok sık gördüğümüz **PKCS#7** standardına göre yapar.

Eğer loader kodunuz, bellekteki bu fazlalık dolgu byte'larını temizlemeden payload'u çalıştırmaya  kalkarsa, işlemci bu dolgu byte'larını birer Assembly talimatı  olarak okumaya çalışır. Ve bundan dolayı süreç anında "Access Violation" veya "Illegal Instruction" hatası vererek çöker.

Bunu önlemek için payload'un sonuna gidip o padding kısmını temizlememiz şart:
```c
BYTE padValue = pDecodedBuffer[totalBufferSize - 1];
```

İlk adımda, çözülmüş bellek alanının en sonundaki byte'ı okuyoruz. PKCS#7 standardı oldukça basit bir mantığa dayanır: Eklenen **padding** değeri, hizalamayı sağlamak için eklenen byte sayısına eşittir. Yani payload'u 4 byte'ın katlarına tamamlamak için 3 byte'lık bir **padding** eklendiyse, son 3 byte `0x03, 0x03, 0x03` olacaktır. Biz sadece son byte'ı okuyarak bu **padding miktarının** ne olduğunu (örneğimizde 3) öğreniyoruz.

```c
if (padValue == 0 || padValue > 4 || padValue > totalBufferSize) 
{
    HeapFree(GetProcessHeap(), 0, pDecodedBuffer);
    return NULL;
}
```

Bu kontrol satırı, kodun güvenliğini ve stabilitesini sağlayan ana unsurlardan biridir. Bir IPv4 adresi en fazla 4 byte olabileceğine göre, uygulanan **padding değeri** matematiksel olarak sadece 1, 2, 3 veya 4 olabilir. Eğer okuduğumuz `padValue` 0 ise veya 4'ten büyükse, verinin dizilimi bir şekilde bozulmuş demektir. Kod bu durumda körü körüne ilerlemeyi reddedip belleği temizleyerek operasyonu iptal eder.

```c
for (BYTE i = 1; i <= padValue; i++) 
{
    if (pDecodedBuffer[totalBufferSize - i] != padValue) 
    {
        HeapFree(GetProcessHeap(), 0, pDecodedBuffer);
        return NULL;
    }
}
```
 Bu verinin gerçekten geçerli bir **padding dizilimi** olup olmadığını doğrulamamız gerekir. Yukarıdaki döngü, tespit edilen **padding boyutu** kadar sondan geriye doğru okuma yapar. Eğer `padValue` 3 ise, geriye dönük okuduğu 3 byte'ın hepsinin gerçekten `0x03` olduğunu teyit eder. Biri bile farklıysa ortada bozuk (**corrupted**) bir veri vardır ve işlem iptal edilir.

```c
*DecodedSize = totalBufferSize - padValue;
```
Son adımda, başta ayırdığımız toplam **buffer boyutundan** **padding miktarını** çıkarıyoruz. Artık elimizde `*DecodedSize` boyutunda, çalıştırılmaya tamamen hazır, pürüzsüz ve **padding byte'larından arındırılmış saf bir payload** var. 

Ofansif güvenlik araştırmalarında işin temeli; işletim sisteminin belleği nasıl yönettiğini bilmek, C dili içerisindeki pointer'ların donanımsal karşılığını kavramak ve API'lerin tip kontrollerini (type-checking) nasıl kendi lehinize esnetebileceğinizi anlamaktan geçer.

Dışarıdan bakıldığında ağ yöneticileri için yazılmış sıradan bir string dönüştürme fonksiyonunun, biraz pointer aritmetiği ve doğru bir **Type-Punning** yaklaşımı ile nasıl kusursuz bir shellcode çözücüye dönüştüğünü gördük. Savunma mimarilerini ve malware analizini zorlaştıran şeyler sadece karmaşık şifreleme algoritmaları değil sistemin kendi olağan işleyişini, yine sisteme karşı kullanan bu zarif mühendislik yaklaşımlarıdır.

