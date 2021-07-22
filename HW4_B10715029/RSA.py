from typing import List # 3.5
import secrets # 3.6
import random
import sys

def exGCD(a:int, b:int) -> List[int]:
  x0, y0 = 1, 0
  x1, y1 = 0, 1

  while (b != 0):
    q = a // b
    x0, x1 = x1, x0-q*x1
    y0, y1 = y1, y0-q*y1

    a, b = b, a%b
  return [a, x0, y0]
def gcd(a:int, b:int) -> int:
  return exGCD(a, b)[0]

def get_e(phi:int) -> int:
  for e in range(2, phi):
    if (gcd(e, phi) == 1):
      return e
  return 1
def inv(a:int, mod:int) -> int:
  # ax + by = gcd(a,b)
  # ax = (-y)b + gcd(a,b)
  # ed = (-k)phi + gcd(e, phi)
  # ed = (-k)phi + 1
  # ed (%phi) = 1
  g, x, y = exGCD(a, mod)
  
  assert(g == 1)
  if(x < 0):
    x += mod
  return x


def RandomNumberGenerator(k:int=1024) -> int:
  return secrets.randbits(k)
def primeTest(n:int, witness:int=3) -> bool:
  if (n%2 == 0):
    return (n==2) # even is prime iff n == 2
  elif (n == 1): # probably bug in miller rabin test
    return False
  elif (n == 3): # probably bug in miller rabin test
    return True
  else:
    # miller rabin test
    p_temp = n - 1
    r = 0
    while (p_temp%2 == 0):
      r += 1
      p_temp //= 2
    d = p_temp

    for w in range(witness):
      a = random.randint(2, n-2)
      x = SquareAndMultiply(a, d, n)
      if (x != 1 and x != (n-1)):
        for i in range(r-1):
          x = (x * x) % n
          if (x == (n-1)):
            break # witness pass

        if (x != (n-1)):
          return False

    return True # probable prime

def primeGen(k:int=1024) -> int:
  n = RandomNumberGenerator(k)
  while (primeTest(n) == False):
    n = RandomNumberGenerator(k)
  return n


def SquareAndMultiply(x:int, h:int, n:int) -> int:
  h_bin = bin(h)[2:]
  result = 1
  for b in h_bin:
    result = (result ** 2) % n
    if (b == '1'):
      result = (result * x) % n
      
  return result


def CRT(x:int, d:int, n:int, p:int, q:int) -> int:
  xp = x % p
  xq = x % q

  yp = SquareAndMultiply(xp, d%(p-1), p)
  yq = SquareAndMultiply(xq, d%(q-1), q)

  cp = inv(q, p)
  cq = inv(p, q)
  y = ((q * cp) * yp + (p * cq) * yq) % n
  return y


def RSA_init() -> List[int]:
  random.seed()
  #p = 22441
  #q = 10271
  p = primeGen(1024)
  q = primeGen(1024)
  e, d, n = RSA_keyGen(p, q)
  
  return [e, d, n, p, q]
def RSA_keyGen(p:int, q:int) -> List[int]:
  n = p * q
  phi = (p-1) * (q-1)
  e = get_e(phi)
  #e = 19403
  d = inv(e, phi)
  return [e, d, n]

def RSA_enc(plain:int, e:int, n:int) -> int:
  return SquareAndMultiply(plain, e, n)
def RSA_dec(cipher:int, d:int, n:int, p:int=-1, q:int=-1) -> int:
  if (p == -1 or q == -1):
    return SquareAndMultiply(cipher, d, n)
  else:
    return CRT(cipher, d, n, p, q)



def main():
  print("[Program Start]")

  data = RandomNumberGenerator(1024)
  mode = "test"
  p = -1
  q = -1
  n = -1
  e = -1
  d = -1
  for i in range(1, len(sys.argv)):
    if (sys.argv[i] == '--mode'):
      i = i + 1
      if (sys.argv[i] in ["encrypt", "decrypt", "test"]):
        mode = sys.argv[i]
      else:
        print("Input mode is not support. Use default.")
    elif (sys.argv[i] == '--data'):
      i = i + 1
      if ((sys.argv[i]).isdigit()):
        data = int(sys.argv[i])
      else:
        print("Input data is not a number. Use default.")
    elif (sys.argv[i] == '--p'):
      i = i + 1
      if ((sys.argv[i]).isdigit()):
        p = int(sys.argv[i])
      else:
        print("Input p is not a number. Use default.")
    elif (sys.argv[i] == '--q'):
      i = i + 1
      if ((sys.argv[i]).isdigit()):
        q = int(sys.argv[i])
      else:
        print("Input q is not a number. Use default.")
    elif (sys.argv[i] == '--n'):
      i = i + 1
      if ((sys.argv[i]).isdigit()):
        n = int(sys.argv[i])
      else:
        print("Input n is not a number. Use default.")
    elif (sys.argv[i] == '--e'):
      i = i + 1
      if ((sys.argv[i]).isdigit()):
        e = int(sys.argv[i])
      else:
        print("Input e is not a number. Use default.")
    elif (sys.argv[i] == '--d'):
      i = i + 1
      if ((sys.argv[i]).isdigit()):
        d = int(sys.argv[i])
      else:
        print("Input d is not a number. Use default.")

  #e, d, n, p, q = RSA_init()
  
  if (mode == "encrypt"):
    if (e == -1 or n == -1):
      if (p == -1 or q == -1): # no input any key
        e, _d, n, _p, _q = RSA_init()
      else: # has p, q
        e, _d, n = RSA_keyGen(p, q)

    print(RSA_enc(data, e, n))
  elif (mode == "decrypt"):
    if (d == -1 or n == -1):
      if (p == -1 or q == -1): # no input any key
        _e, d, n, p, q = RSA_init()
      else: # has p, q
        _e, d, n = RSA_keyGen(p, q)
    else:
      if (p == -1 or q == -1): # has d, n no p, q
        p = -1
        q = -1

    print(RSA_dec(data, d, n, p, q))
  elif (mode == "test"):
    if (e == -1 or d == -1 or n == -1):
      if (p == -1 or q == -1): # no input any key
        e, d, n, p, q = RSA_init()
      else:  # has p, q
        e, d, n = RSA_keyGen(p, q)
    else:
      if (p == -1 or q == -1): # has e, d, n no p, q
        p = -1
        q = -1

    cipher = RSA_enc(data, e, n)
    plain = RSA_dec(cipher, d, n, p, q)
    print("Ori:", data)
    print("Enc:", cipher)
    print("Dec:", plain)
    print("Equ:", data == plain)

  print("[Program End]")

if __name__ == "__main__":
    main()