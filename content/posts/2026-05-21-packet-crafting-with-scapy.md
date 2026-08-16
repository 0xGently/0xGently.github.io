---
layout: post
title: "Packet Crafting with Scapy"
author: "0xGently"
draft: false
tags: [Python, Scapy, Ağ Güvenliği]
---

![Scapy Logo](/home/Gently/maldev/scapy-image.webp)


Ağ güvenliği ve siber güvenlik dünyasında, bir paketin nasıl oluştuğunu, nasıl manipüle edilebileceğini ve özel paketler oluşturmayı bilmek çok kritik bir beceridir. Python programlama dili ve Scapy kütüphanesi, bu becerileri öğrenmek için mükemmel bir platform sunar. Bu yazıda, Scapy kullanarak ağ paketlerini oluşturmanın ve analiz etmenin temellerini aşama aşama detaylandıracağım.

## 1. Scapy Nedir ve Neden Önemlidir?

Scapy, Python ile yazılmış güçlü bir ağ paket manipülasyon kütüphanesidir. Temel olarak şunları yapmamıza olanak sağlar:

- Ağ trafiğini yakalamak (sniffing)
- Paketleri incelemek ve analiz etmek
- Özel paketler oluşturmak (crafting)
- Paketleri değiştirmek (manipulation)
- Ağda testler ve güvenlik senaryoları simüle etmek

Scapy’nin gücü, onu hem pasif hem aktif ağ çalışmalarında kullanabilmekten gelir. Pasif olarak, ağdaki mevcut trafiği analiz edebiliriz; aktif olarak ise hedef sistemlere özel paketler gönderip tepki analizleri yapabiliriz.

## 2. Temel Kavramlar

Paket manipülasyonu ve crafting yapmadan önce, ağ paketlerinin yapılarını anlamak çok önemlidir. Ağ paketleri, OSI modelinin katmanları ile doğrudan ilişkilidir:

![OSI Modeli Katmanları](/assets/img/scapy-image-2-.webp)

- **Ethernet (Data Link Layer)**: Paketlerin fiziksel ağda taşınmasını sağlar. Kaynak ve hedef MAC adreslerini içerir.
- **IP (Network Layer)**: Paketlerin ağlar arasında yönlendirilmesini sağlar. IP adresleri buradadır.
- **TCP/UDP (Transport Layer)**: Veri iletim protokolleridir. TCP bağlantı odaklıdır, UDP ise bağlantısızdır.
- **Application Layer**: HTTP, DNS, FTP gibi üst seviye protokoller buradadır.

Scapy ile her katmanda paket manipülasyonu yapabiliriz. Örneğin, bir TCP paketinin port numarasını değiştirebilir, bir ICMP paketini spoof edebilir veya DNS sorgularını taklit edebiliriz.

## 3. Scapy ile Çalışmanın Temel Mantığı

Scapy ile çalışırken üç temel kavramı bilmek gerekiyor:

1. **Paket Oluşturma (Packet Crafting)** Scapy ile bir paket oluştururken, her katmanı bağımsız bir obje olarak düşünebiliriz. Örneğin, IP katmanı, TCP katmanı ve bir payload (veri) katmanı oluşturursun ve bunları üst üste bind (/) ile birleştirirsin.
2. **Paket Gönderme (Sending Packets)** Craft ettiğin paketi göndermek için Scapy’nin `send()` veya `sr()` gibi fonksiyonlarını kullanırız. `send()` genellikle TCP/IP katmanı için, `sendp()` ise Ethernet katmanı için kullanılır.
3. **Paket Yakalama (Sniffing)** Ağdaki paketleri yakalamak için `sniff()` fonksiyonunu kullanırız. Bu, gerçek zamanlı analiz ve saldırı simülasyonları için önemlidir. Filtreleme yapabilir, sadece belirli protokolleri veya portları yakalayabiliriz.

Şimdi ise bu kısımlar detaylı olarak anlatılacaktır.

## 4. Paket Oluşturma (Packet Crafting)

Scapy’de **paket oluşturmak**, temel olarak ağdaki veri birimini (paketi) kendi istediğin şekilde tasarlamak demektir. Buradaki mantık OSI katmanları üzerinden çalışır:

### Katman Mantığı

- Her katman, OSI modelindeki bir katmanı temsil eder: Ethernet (Layer 2), IP (Layer 3), TCP/UDP (Layer 4), Payload (Layer 7).
- Her katman bağımsız bir obje olarak oluşturulur. Örneğin, `IP()` bir IP katmanı objesidir, `TCP()` bir TCP katmanı objesidir.
- Katmanlar `/` operatörü ile üst üste bindirilir. Yani:

`Ethernet / IP / TCP / Payload`

Bu yapıyı oluşturmak, paketin ağda nasıl taşınacağını ve hedefin nasıl yorumlayacağını belirler.

### Bind Mantığı

- **Alt katman** üst katmanın taşıyıcı katmanı gibidir. Yani TCP, IP üzerinden taşınır; IP, Ethernet üzerinden.
- Bind mantığı, Scapy’de `/` operatörü ile yapılır. Örnek: `ip_layer / tcp_layer / Raw("data")`.
- Bu, OSI modeline göre doğal bir paket hiyerarşisi oluşturur.

### Crafting Mantığı

1. Önce hangi protokolü kullanacağımızı seçeriz (IP, TCP, UDP, ICMP).
2. Katmanın alanlarını özelleştirirsin:
   - IP: `src`, `dst`
   - TCP: `sport`, `dport`, `flags`
   - Payload: `Raw(load="veri")`
3. Katmanları `/` ile birleştirirsin.
4. Artık paketin craft edilmiş ve gönderilmeye hazırdır.

**Örnek Mantık Akışı:**

- Hedef IP’ye TCP SYN paketi göndermek istiyorsun.
- IP katmanı oluştur → TCP katmanı oluştur → Payload ekle (opsiyonel) → `/` ile birleştir → paket hazır.

```python
packet = IP(dst="192.168.1.30") / TCP(dport=80) / Raw(load="Merhaba Dünya!")
```
## 5. Paket Gönderme (Sending Packets)

Craft edilmiş paketi göndermek, paket oluşturma kadar önemli bir adımdır. Scapy bunu iki ana seviyede yapmamıza izin verir:

### 5.1 Network Layer (IP Katmanı) Gönderimi

- TCP/IP katmanındaki paketler için `send()` veya `sr()` kullanılır.
- `send()`: Paketi gönderir, cevap beklemez.
- `sr()`: Paketi gönderir ve cevabı bekler, genellikle request-response senaryolarında kullanılır.

**Mantık:** IP katmanını hedefe gönderiyoruz. TCP veya UDP bu katmanın üstünde, payload üstünde taşınıyor. Burada **“2. katmandan gönderme”** değil, **IP katmanından** gönderim söz konusu. OSI’ye göre Layer 3 seviyesinde işlem yapıyoruz.

### 5.2 Data Link Layer (Ethernet Katmanı) Gönderimi

- Ethernet seviyesinde paketler için `sendp()` veya `srp()` kullanılır.
- Bu seviyede, MAC adresleri doğrudan önemlidir.
- OSI modeline göre Layer 2’de işlem yapıyoruz.

**Mantık:** IP katmanı olmadan Ethernet çerçevesi üzerinden veri gönderiyoruz. Bu genellikle düşük seviye testlerde veya LAN içi senaryolarda kullanılır.

## 6. Paket Yakalama (Sniffing)

Sniffing, ağdaki paketleri gerçek zamanlı yakalamak ve analiz etmektir. Scapy bunu `sniff()` fonksiyonu ile sağlar.

### Sniffing Mantığı

1. **Filtreleme:**
   - Tüm trafiği yakalamak yerine, belirli protokolleri (TCP, ICMP, UDP) veya portları filtreleyebiliriz.
   - Örnek: `filter="tcp and port 80"`

2. **Katman Katman Analiz:**
   - Yakalanan paketler `packet.show()` ile detaylı olarak analiz edebiliriz.
   - Katmanlar ayrı ayrı görülebilir: IP, TCP, payload.

3. **Gerçek Zamanlı veya Belgeye Kaydetme:**
   - `sniff(count=10)` ile 10 paket yakalanır.
   - Yakalanan paketleri bir pcap dosyasına kaydedip sonra analiz etmek mümkündür.

Bu üç adımı — paket oluşturma, gönderme ve sniffing — doğru kavradığında, OSI katmanları arasındaki veri akışını hem analiz edebilir hem de kontrollü bir şekilde manipüle ederek güvenlik testlerinde kullanabiliriz.
