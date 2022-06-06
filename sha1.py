int32_max = 2 ** 32 - 1
int448_max = 2 ** 448 - 1
int512_max = 2 ** 512 - 1


# Разбиваем большое число на 32-битные слова
def hex_to_words(value):
    lst = []
    while value:
        lst.append((value & int32_max))
        value = value >> 32
    return lst


# Представление текстовой строки ввиде байтов
def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = int.from_bytes(text.encode(encoding, errors), 'big')
    return bits


# Побитовый сдвиг влево
def shift_left(num, shift):
    return int32_max & (num << shift)


# Циклический сдвиг влево
def rotateLeft(num, shift):
    size = 32
    return ((num >> size - shift) | (num << shift)) & int512_max


# Итератор чанков
def chunk_iter(message):
    while message:
        # Отсекаем 448 правых бит
        chunk = message & int448_max
        # Считаем длинну отсеченного числа(ведущие нули не считаем)
        size = len(bin(chunk)) - 2
        # Добавляем 1 справа
        chunk = (chunk << 1) + 1
        # Добавляем нули справа чтобы размер составлял 448 бит после чего добавляем справа еще 64 бит(размер чанка size)
        chunk = chunk << (512 - size - 1)
        chunk += size
        # Возвращаем 512-битный блок(448 бит информации и 64 бит размер чанка)
        yield chunk
        message = message >> 448


# Подсчет хэш-значения числа message
def SHA1(message, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0):
    # Если тип message строка преобразуем ее в число
    if type(message) == str:
        message = text_to_bits(message)

    ml = len(bin(message)) - 2
    hash = 0

    # Разбиваем message на чанки и для каждого считаем хэш после чего складываем хэши чанков по модулю 2^512
    for chunk in chunk_iter(message):
        # Разбиваем чанк на слова
        w = hex_to_words(chunk)

        # Вычисляем массив w
        for i in range(16, 80):
            w.append(rotateLeft((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 5))

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # 80 раз пересчитываем a, b, c, d, e
        for i in range(80):
            if 0 <= i <= 19:
                f = (b and c) or ((not b) and d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b and c) or (b and d) or (c and d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            temp = (rotateLeft(a, 5) + f + e + k + w[i]) % (2 ** 32)
            e = d
            d = c
            c = rotateLeft(b, 30)
            b = a
            a = temp
        h0 = h0 + a % (2 ** 32)
        h1 = h1 + b % (2 ** 32)
        h2 = h2 + c % (2 ** 32)
        h3 = h3 + d % (2 ** 32)
        h4 = h4 + e % (2 ** 32)
        # Конкатенируем слова h0, h1, h2, h3, h4 получая 160-битное хеш-значение для чанка
        chunk_hash = h0 << 128 | h1 << 96 | h2 << 64 | h3 << 32 | h4

        hash += chunk_hash
        hash %= 1 << 160
    return hash


message = int(input("Введите число:\n"))
print(hex(SHA1(message))[2:])
message = input("Введите строку:\n")
print(hex(SHA1(message))[2:])
