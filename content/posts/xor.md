---
title: XOR Şifreleme
date: 2026-04-15
draft: false
author: 0xGently
tags:
  - encryption
---

## XOR Şifrelemesi

Malware geliştirme dünyasında, yazdığınız zararlı yazılımın ömrünü belirleyen en kritik faktörlerden biri **payload'unuzu ne kadar iyi gizleyebildiğinizdir**. Eğer bir shellcode'u veya PE dosyasını belleğe açık (plain-text) bir şekilde gömerseniz, statik analiz araçları ve Antivirüs (AV) imzaları saniyeler içinde sizi yakalayacaktır.

İşte tam bu noktada **Payload Encryption** devreye girer. Bu yazımızda, zararlı yazılım dünyasının en temel ama en çok modifiye edilen şifreleme mantıklarından birini, **XOR** algoritmasını inceleyeceğiz. İşi temelden alıp kompleks (Rolling/Position-Dependent) yapılara doğru evrilteceğiz.

**Not**: Bu metinde anlattığım kodun tamamını https://github.com/0xGently/Malware-Dev-Analysis-Library/blob/main/Payload-Encryption-and-Obfuscation/01-XOR/xor.c adresinde bulabilirsiniz
### XOR (Exclusive OR)

XOR operatörü (`^`), kriptografide ve zararlı yazılım geliştirmede vazgeçilmezdir çünkü **simetriktir**. Yani bir veriyi şifrelemek ve o veriyi çözmek için aynı fonksiyonu kullanırsınız.

- `Veri ^ Anahtar = Şifreli Veri`

- `Şifreli Veri ^ Anahtar = Veri`

Bu durum, malware geliştiricisine inanılmaz bir esneklik ve kod tasarrufu sağlar. Ekstra bir "şifre çözücü" (decryptor) algoritması yazmanıza gerek kalmaz. Şimdi bu mantığın koda nasıl döküldüğüne bakalım.

### Single-Byte Key XOR

İşe en basit haliyle, tek bir bayt (Single-Byte) kullanarak tüm payload'u şifreleyen fonksiyonumuzla başlayalım.
```c
static VOID SingleKeyXor(IN PBYTE pPayload, IN SIZE_T sPayloadSize, IN const BYTE bXorKey)
{
    for (size_t x = 0; x < sPayloadSize; x++)
    {
        pPayload[x] = pPayload[x] ^ bXorKey;
    }
}
```
Bu fonksiyon üç basit parametre alıyor:
1. `pPayload`: Şifrelenecek (veya çözülecek) verinin bellek adresi.
2. `sPayloadSize`: Verinin toplam boyutu.
3. `bXorKey`: İşlemi gerçekleştireceğimiz tek baytlık anahtarımız (Örn: `0xAA`).

Buradaki mantık düz ve basittir: Bir `for` döngüsü oluşturulur ve payload'un başından sonuna kadar tek tek ilerlenir. Her bir bayt, bizim belirlediğimiz `bXorKey` ile XOR işlemine sokulur ve eski yerine geri yazılır.
Bu yöntem AV'lerin statik imza taramalarından (signature-based detection) kaçmak için başlangıçta işe yarasa da, günümüzde oldukça yetersizdir. Çünkü tek baytlık bir anahtar kullandığınızda, payload içindeki birbirini tekrar eden baytlar (örneğin arka arkaya gelen `0x00` null baytları), şifrelendikten sonra da sürekli aynı değeri üretecektir.

### Advanced Rolling XOR

Tek baytlık anahtarın zayıflığını gördük. Güvenlik çözümlerini atlatmak için her baytı farklı bir sonuç üreten bir sisteme ihtiyacımız var.

Bunun için sadece sabit bir değer kullanmak yerine, hem çoklu bayt (Multi-Byte) anahtar dizisinden beslenen hem de bulunduğu konuma göre sürekli şekil değiştiren (Position-Dependent) özel bir Rolling XOR algoritması tercih edeceğiz.

```c
static VOID CustomRollingXor(IN PBYTE dataBuffer, IN SIZE_T dataLen, IN PBYTE keyBuffer, IN SIZE_T keyLen)
{
    SIZE_T keyIndex = 0;

    for (SIZE_T i = 0; i < dataLen; i++)
    {
        // 1. Adım: Sadece o anki konuma (i) özel dinamik maskeyi (salt) hesapla
        BYTE positionSalt = (BYTE)(i * 0x9B) ^ (BYTE)(i >> 3);

        // 2. Adım: Veriyi hem anahtarla hem de konum değeriyle XOR'la
        dataBuffer[i] = dataBuffer[i] ^ keyBuffer[keyIndex] ^ positionSalt;

        // 3. Adım: Anahtarın indeksini ilerlet, sonuna geldiyse başa sar
        keyIndex++;
        if (keyIndex == keyLen) 
        {
            keyIndex = 0;
        }
    }
}
```
Bu fonksiyon, sıradan bir XOR'u alıp çok daha karmaşık hale getiriyor. Nasıl çalıştığını adım adım açıklayayım:

**1. Multi-Byte ve Başa Saran (Rolling) Anahtar Yapısı (`keyIndex`)** Artık elimizde tek bir şifreleme baytı değil, uzun bir dizi (array) var (örneğin `0xDE, 0xAD, 0xBE, 0xEF` gibi). Kodumuzdaki `keyIndex` sayacı, bu şifre dizisinin üzerinde sırayla ilerliyor. Anahtarın sonuna ulaşıldığında ise `if (keyIndex == keyLen)` koşulu devreye giriyor ve sayaç sıfırlanıp tekrar anahtarın başına dönüyor. Buna literatürde "Rolling" işlemi diyoruz; böylece veri ne kadar uzun olursa olsun, anahtarımız sürekli kendini tekrar ederek kesintisiz bir şifreleme sunuyor.

**2. Konum Odaklı Mutasyon (`positionSalt`)** Fonksiyonu asıl güçlü kılan ve statik analiz araçlarını çaresiz bırakan kısım tam olarak burasıdır. Şifreleme işlemine sadece anahtarımızı değil, verinin o anki indeks numarasını (`i`) da dahil ediyoruz. İşlemin mantığını netleştirmek için bunu `positionSalt` adlı bir değişkende topladık:

- `i * 0x9B`: O anki konum değeri, rastgele belirlenmiş bir çarpanla (`0x9B`) çarpılıyor.
    
- `i >> 3`: Ardından aynı konum değeri 3 bit sağa kaydırılarak (bitwise right shift) işleme tekrar XOR'lanıyor.
    

Elde ettiğimiz bu dinamik tuzak, asıl anahtarımızla birleşerek veriye nüfuz ediyor. Bu tekniğin en büyük avantajı şudur: Şifreleyeceğiniz veri bloğunun içinde art arda yüz tane aynı karakter (örneğin `0x41` yani 'A' baytı) olsa bile, her birinin indeksi (`i`) farklı olduğu için şifrelenmiş halleri birbirinden **tamamen farklı** olacaktır.

Kendi indeksine göre mutasyona uğrayan bu yapının matematiksel olarak tahmin edilmesi ve kırılması, tek baytlık geleneksel XOR yöntemlerine kıyasla astronomik ölçüde zordur.

## Bu Teknik Nasıl Tespit Edilir?

### 1. Statik Analiz 
Statik Analiz kısmında yakalayabileceğimiz ipuçları şunlardır:

- **Şüpheli Matematiksel İmzalar:** Normal bir programda `XOR` işlemi sıklıkla kullanılabilir. Ancak bir kod bloğunun içinde art arda `XOR`, `MUL` (Çarpma) ve `SHR` (Sağa Kaydırma) komutları bir `for` döngüsü (`CMP` ve `JMP` blokları) içine hapsedilmişse, bu yüksek ihtimalle bir "Decryption Stub" olarak işaretlenir.
    
- **Yüksek Entropi:** Zararlı yazılımın `.data` veya `.rsrc` bölümlerinde anlamsız, tamamen rastgele karakterlerden oluşan büyük bir veri yığını (yüksek entropi) varsa, o bölümün içerisinde şifrelenme vb bir durum olduğundan şüphelenilir.

### 2. Dinamik Analiz
Dinamik Analiz kısmında ise şunlara bakılabilir:

1. **Hardware Breakpoint:** Statik analizde tespit edilen o yüksek entropili şifreli verinin bellek adresine "Hardware Breakpoint" atılır.
    
2. **Döngüyü Atlama:** Kod çalışmaya başladığında ve o veriye dokunulduğunda debugger durur.  karmaşık döngünün içine girip adım adım takip etmek (Step Into) yerine, döngünün bittiği ilk satıra breakpoint atar ve program devam ettirilir (Run).
    
3. **Memory Dump:** Döngü bittiği an program tekrar durur. O süslü Rolling XOR algoritması işini yapmış ve bitirmiştir.bellek penceresine baktığında, şifreli verinin yerinde **tamamen çözülmüş (plain-text) asıl zararlı payload'u** görülürr. Sağ tıklayıp "Dump to File" diyerek asıl zararlı saniyeler içinde ele geçirilir.
