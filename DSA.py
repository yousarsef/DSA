from random import randrange
from gmpy2 import xmpz, to_binary, invert, powmod, is_prime
from hashlib import sha1

def generer_p_et_q(L, N):
    g = N
    n = (L - 1) // g
    b = (L - 1) % g
    while True:
        # générer q
        while True:
            s = xmpz(randrange(1, 2 ** (g)))
            a = sha1(to_binary(s)).hexdigest()
            z1 = xmpz((s + 1) % (2 ** g))
            z = sha1(to_binary(z1)).hexdigest()
            U = int(a, 16) ^ int(z, 16)
            mask = 2 ** (N - 1) + 1
            q = U | mask
            if is_prime(q, 20):
                break
        # générer p
        i = 0 
        j = 2
        while i < 4096:
            V = []
            for k in range(n + 1):
                arg = xmpz((s + j + k) % (2 ** g))
                z1v = sha1(to_binary(arg)).hexdigest()
                V.append(int(z1v, 16))
            W = 0
            for q1 in range(0, n):
                W += V[q1] * 2 ** (160 * q1)
            W += (V[n] % 2 ** b) * 2 ** (160 * n)
            X = W + 2 ** (L - 1)
            c = X % (2 * q)
            p = X - c + 1
            if p >= 2 ** (L - 1):
                if is_prime(p, 10):
                    return p, q
            i += 1
            j += n + 1


def generer_g(p, q):
    while True:
        h = randrange(2, p - 1)
        exp = xmpz((p - 1) // q)
        g = powmod(h, exp, p)
        if g > 1:
            break
    return g

def generer_cles(g, p, q):
    x = randrange(2, q)
    y = powmod(g, x, p)
    return x, y

def generer_parametres(L, N):
    p, q = generer_p_et_q(L, N)
    g = generer_g(p, q)
    return p, q, g

def signer(M, p, q, g, x):
    if not validation_parametres(p, q, g):
        raise Exception("Paramètres non valides")
    while True:
        k = randrange(2, q)  # k < q
        r = powmod(g, k, p) % q
        m = int(sha1(M).hexdigest(), 16)
        try:
            s = (invert(k, q) * (m + x * r)) % q
            return r, s
        except ZeroDivisionError:
            pass

def verifier(M, r, s, p, q, g, y):
    if not validation_parametres(p, q, g):
        raise Exception("Paramètres non valides")
    if not validation_signer(r, s, q):
        return False
    try:
        w = invert(s, q)
    except ZeroDivisionError:
        return False
    m = int(sha1(M).hexdigest(), 16)
    u1 = (m * w) % q
    u2 = (r * w) % q
    v = (powmod(g, u1, p) * powmod(y, u2, p)) % p % q
    if v == r:
        return True
    return False

def validation_parametres(p, q, g):
    if is_prime(p) and is_prime(q):
        return True
    if powmod(g, q, p) == 1 and g > 1 and (p - 1) % q:
        return True
    return False

def validation_signer(r, s, q):
    if r < 0 and r > q:
        return False
    if s < 0 and s > q:
        return False
    return True

if __name__ == "__main__":
    N = 160
    L = 2048
    p, q, g = generer_parametres(L, N)
    x, y = generer_cles(g, p, q)

    text = "Youssef"
    M = str.encode(text, "ascii")
    r, s = signer(M, p, q, g, x)
    if verifier(M, r, s, p, q, g, y):
        print('Tout est vérifié')
    print(M, r, s, p, q, g, y, x, sep='\n')