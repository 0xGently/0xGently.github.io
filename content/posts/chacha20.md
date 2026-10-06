---
title: Chacha20 Şifreleme
date: 2026-04-01
draft: false
author: 0xGently
tags:
  - encryption
---

## ChaCha20 Şifrelemesi

Bu metinde Chacha20 den bahsedeceğim.

Dosya boyutu ve basitlik her şeydir. ChaCha20'yi tercih etmemizin tek sebebi var: **Küçük, hızlı ve ekstradan deşifre bloğu yazmanıza gerek bırakmıyor.**

Peki neden ChaCha20'yi seçiyoruz? Çünkü inanılmaz derecede hızlıdır, işlemcinin özel şifreleme donanımlarına (AES-NI gibi) ihtiyaç duymaz ve C/C++ ile sıfırdan yazması (implementasyonu) çok daha zahmetsizdir. Ayrıca, şifreleme ve deşifreleme (encrypt/decrypt) işlemleri için birebir aynı kodu kullanırız, bu da yazdığımız zararlı yazılımın boyutunu (stub size) küçültür.

Bugün, standart bir ChaCha20 C kodu üzerinden bu işin nasıl çalıştığına bakacağız. Yüzlerce satırlık bellek yönetimi veya hata kontrolleriyle uğraşmadan, algoritmanın sadece en can alıcı 3 noktasına odaklanıyoruz. 

**Not**:  Kodun geri kalanını incelemek isterseniz şu link üzerinden bakabilirsiniz:
https://www.oryx-embedded.com/doc/chacha_8c_source.html

### 1. Matris Oluşturmak

ChaCha20, bir akış şifrelemesidir (Stream Cipher). Amacı, elimizdeki anahtarı (key) kullanarak çok uzun, rastgele gibi görünen bir veri akışı (keystream) üretmektir. Her şey, bellekte 4x4'lük (16 kelime / 64 byte) bir tablo (matris) oluşturmamızla başlar.

Kodumuzun `chachaInit` fonksiyonuna baktığımızda, bu tablonun ilk satırının şu sabit değerlerle doldurulduğunu görüyoruz:

```c
// 32-byte (256-bit) anahtar için matrisin ilk 4 kelimesi (State)
w[0] = 0x61707865;
w[1] = 0x3320646E;
w[2] = 0x79622D32;
w[3] = 0x6B206574;
```

Bu hex değerleri yan yana koyup ASCII'ye çevirdiğinizde **"expand 32-byte k"** metni ortaya çıkar. Tablonun geri kalanını ise bizim belirlediğimiz 32-byte anahtar (key) ve sayaç/nonce değerleri doldurur.

**NOT**: Eğer bir gün Chacha20 dışında bir şifreleme fonksiyonu kullanıp kodun herhangi bir kısmına bu kısmı eklerseniz bu kodu reverse eden kişilerin kafasını karıştırmış yanıltmış olursunuz. Yani en azından işe yararlılığını kesin olarak emin olmamakla birlikte benim aklıma gelen mantıklı bir fikir.
### 2. ARX ve Karıştırma

İşte güvenliği sağlayan şey, o kurduğumuz tablonun içindeki değerlerin, şifreleme yapılmadan önce çok karmaşık bir matematiksel işlemle birbirine katılmasıdır. Kodun asıl motoru olan `QUARTER_ROUND` makrosuna yakından bakalım:

```go
#define QUARTER_ROUND(a, b, c, d) \
{ \
   a += b; \
   d ^= a; \
   d = ROL32(d, 16); \
   c += d; \
   b ^= c; \
   b = ROL32(b, 12); \
   a += b; \
   d ^= a; \
   d = ROL32(d, 8); \
   c += d; \
   b ^= c; \
   b = ROL32(b, 7); \
}
```

Dikkat ederseniz burada sadece üç basit işlem var: **Toplama (+=), XOR (^=) ve Sola Kaydırma (ROL32)**. Kriptografi dünyasında buna ARX mimarisi denir. İşlemciyi hiç yormaz ama veriyi karmaşık derecede bir hale getirir.

Peki bu makro tabloya nasıl uygulanıyor? `chachaProcessBlock` fonksiyonunda şu yapıyı görürüz:
```c
// Önce Sütunlar karıştırılır...
QUARTER_ROUND(w[0], w[4], w[8],  w[12]);
QUARTER_ROUND(w[1], w[5], w[9],  w[13]);
QUARTER_ROUND(w[2], w[6], w[10], w[14]);
QUARTER_ROUND(w[3], w[7], w[11], w[15]);

// ...sonra Çapraz (Diagonal) elemanlar karıştırılır.
QUARTER_ROUND(w[0], w[5], w[10], w[15]);
QUARTER_ROUND(w[1], w[6], w[11], w[12]);
QUARTER_ROUND(w[2], w[7], w[8],  w[13]);
QUARTER_ROUND(w[3], w[4], w[9],  w[14]);
```

Bu yapı tabloyu tam **20 kez** (ChaCha**20** adı buradan gelir) kendi içinde toplar, kaydırır ve XOR'lar. Algoritma 10 kez sütunları, 10 kez de çapraz değerleri işleme sokar. Tıpkı bir Rubik küpünü 20 kez rastgele çevirmek gibi düşünebilirsiniz. Ortaya çıkan Keystream (anahtar akışı) o kadar karışıktır ki, orijinal parolayı bilmeden işlemi geri döndürmek imkansızdır.

### 3. Payload'u Şifrelemek

Tabloyu kurduk, Rubik küpünü çevirip Keystream'i (rastgele akan veriyi) ürettik. Şimdi asıl amacımıza, yani zararlı payload'umuzu şifrelemeye geldik.

Şifrelemenin gerçekleştiği yer sadece şu küçücük `for` döngüsüdür (Kodun `chachaCipher` fonksiyonu içerisinde):
```c
// Payload (input) ile Keystream'i (k) XOR'la
for(i = 0; i < n; i++)
{
   output[i] = input[i] ^ k[i];
}
```
Hazırladığımız o mükemmel karmaşıklıktaki Keystream (`k`), bizim orijinal payload'umuz (`input`) ile byte byte **XOR (^)** işlemine sokulur. Ve tebrikler, artık elinizde tamamen şifrelenmiş, hafızada anlamsız görünen bir veri (`output`) var.

Başta da söylediğim gibi XOR simetrik bir işlemdir. Hedef makinede bu payload'u çalıştırmak istediğinizde, aynı anahtarla aynı akışı üretir ve şifreli veriyi tekrar XOR'larsınız. Orijinal kodunuz belleğe açılır ve çalışmaya hazır hale gelir. Ekstra bir deşifreleme (decryptor) fonksiyonu yazmanıza gerek yoktur. 

Tüm bunların haricinde linkteki koda bakarsanız burada anlattığımdan çok daha uzun olduğunu görürsünüz. Bu kadar kısa bırakmamın sebebi koddan ziyade şifreleme yönteminin mantığını anlatabilmekti. Bu anlattığım kod blokları haricinde kalan kısımlar ise üstünkörü şu şekildedir:
### Matrisin Doldurulma İşlemi
```c
w[4] = LOAD32LE(key);
w[5] = LOAD32LE(key + 4);
w[6] = LOAD32LE(key + 8);
w[7] = LOAD32LE(key + 12);
	....... 
```
Sadece bir veri paketleme (parsing) işlemidir. Dışarıdan verdiğiniz anahtar (key) ve nonce değerleri, tek parça uzun bir veri dizisidir. ChaCha20'nin yapısı 32-bit'lik kutucuklardan oluştuğundan burada if else bloklarında önce genel olarak anahtar 128 bit mi (16 byte) yoksa 256 bit mi (32 byte) bakılır. Sonrasında Nonce değeri 64 bit mi, 96 bit mi yoksa 128 bit mi diye bakılır. Bu boyutları kontrol ettikten sonrada `LOAD32LE` (Load 32-bit Little Endian) fonksiyonu yardımıyla bu uzun veriyi 4'er byte'lık parçalara böler ve matrisin (w dizisinin) ilgili hücrelerine doğru formatta yerleştirir.
### ChachaDeinit Fonksiyonu
```c
void chachaDeinit(ChachaContext *context)
{
   //Clear ChaCha context
   osMemset(context, 0, sizeof(ChachaContext));
}
```
Bu fonksiyonun tek bir amacı vardır: İşlem bittikten sonra RAM i temizlemek. Kriptografik işlemlerde, şifreleme anahtarının veya "State" matrisinin işlem bittikten sonra bellekte kalması güvenlik riski oluşturur. `osMemset`, bu yapının (struct) içini tamamen sıfırlarla doldurarak verileri güvenli bir şekilde siler.
### Toparlarsak
ChaCha20, mantığı aslında çok basittir. "Tabloyu kur, veriyi ARX ile karıştır, payload ile XOR'la." Bütün mantık budur.

