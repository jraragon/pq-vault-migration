"""
P15 -- Modelo analítico de bytes y operaciones asimétricas por arquitectura y suite
(fase F0/F1, previo al preregistro). NO es una medida: aplica los tamaños de la
Tabla 1 del documento de arranque v0.3 a la población sintética de JCP.

Población: la publicada en JCP (2026, 6, 197, Sec. 7.4), archivada en
data/population_jcp_seed42.csv por analysis/make_population.py (D-024).

Proyección sobre las arquitecturas (opción (b) del 16-11-2026, adaptada):
  - n_total  : nodos de la cuenta (carpetas + ficheros)          [JCP]
  - n_f      : elementos de primer nivel bajo la clave de cuenta  [JCP]
  - n_h      : titulares de la cuenta                             [JCP]
  - phi      : fracción de nodos que son ficheros (NUEVO, único parámetro añadido;
               no lo genera JCP). Se informa con análisis de sensibilidad.
  - A1b      : cada elemento de primer nivel es una carpeta cifrada compartida con
               los n_h titulares (supuesto de máximo compartido, cota superior).

Solo se cuentan los bytes que dependen de la suite (claves públicas, claves privadas
almacenadas y textos cifrados de KEM). Las envolturas simétricas AES-KW (40 B) y las
cabeceras de paquete son iguales para todas las suites y se excluyen.
"""
import numpy as np

# ---------------------------------------------------------------- población JCP
# Población publicada (JCP 2026, 6, 197, Sec. 7.4): n_f = min(1 + Poisson(6), n_total).
# Se lee del fichero archivado por make_population.py (independiente de la versión de NumPy).
import os
_POP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "population_jcp_seed42.csv")
_pop = np.loadtxt(_POP, delimiter=",", skiprows=1, dtype=np.int64)
n_total, n_f, n_h = _pop[:, 1], _pop[:, 2], _pop[:, 3]
N = len(n_total)

assert N == 20_000
assert n_total.sum() == 7_557_945, n_total.sum()
assert (1 + n_f + n_h).sum() == 203_149, (1 + n_f + n_h).sum()
assert round(float(np.median(n_total / (1 + n_f + n_h))), 1) == 15.3

# ---------------------------------------------------------------- tamaños (bytes)
# pk bruta, sk almacenada (semilla / expandida), ct.  Tabla 1, v0.3.
RSA_SK = 1767  # RSAPrivateKey, mediana medida
SUITES = {
    "RSA-3072":    dict(pk=398,  sk={"semilla": RSA_SK,        "expandida": RSA_SK},        ct=384),
    "ML-KEM-768":  dict(pk=1184, sk={"semilla": 64,            "expandida": 2400},          ct=1088),
    "ML-KEM-1024": dict(pk=1568, sk={"semilla": 64,            "expandida": 3168},          ct=1568),
    "Híbrido":     dict(pk=1966, sk={"semilla": 64 + RSA_SK,   "expandida": 3168 + RSA_SK}, ct=1952),
}

def modelo(arq, s, fmt, phi):
    """Devuelve (bytes en reposo, bytes reescritos al migrar, ops asimétricas al migrar)
    por cuenta, en arrays de longitud N."""
    pk, sk, ct = s["pk"], s["sk"][fmt], s["ct"]
    cred = n_h * (pk + sk)                      # credencial de cada titular
    n_files = np.round(phi * n_total)
    if arq == "A1":       # frontera en la raíz de la cuenta (JCP)
        rep = cred + n_h * ct
        mig = cred + n_h * ct                   # n_f re-envolturas AES-KW: independientes de la suite
        ops = n_h                               # encapsulados
    elif arq == "A1b":    # frontera en cada carpeta compartida de primer nivel (Nextcloud)
        rep = cred + n_f * n_h * ct
        mig = cred + n_f * n_h * ct
        ops = n_f * n_h
    elif arq == "A2":     # frontera en cada nodo (Proton Drive)
        nodos = n_total * (pk + sk + ct) + n_files * ct   # frase de paso + content key packet
        rep = cred + n_h * ct + nodos                     # raíz compartida a cada titular
        mig = rep                                         # todo nodo tiene clave asimétrica de la suite
        ops = n_total + (n_total + n_files) + n_h         # generaciones + encapsulados
    elif arq == "A3":     # bóveda simétrica, sin compartición por clave pública
        z = np.zeros(N)
        return z, z, z
    return rep.astype(float), mig.astype(float), ops.astype(float)

def kib(x): return x / 1024

if __name__ == "__main__":
    print(f"Población JCP (publicada): {n_total.sum():,} nodos; {(1+n_f+n_h).sum():,} unidades incrementales\n")
    for phi in (0.7, 0.8, 0.9):
        print(f"=== phi (fracción de ficheros) = {phi} ===")
        print(f"{'Arq':4} {'Suite':12} {'sk':9} {'Reposo med. KiB':>16} {'Migración total MiB':>20} {'Ops asim. totales':>18} {'Δ vs RSA (repos., med.)':>24}")
        for arq in ("A1", "A1b", "A2", "A3"):
            for fmt in ("semilla", "expandida"):
                base, _, _ = modelo(arq, SUITES["RSA-3072"], fmt, phi)
                for name, s in SUITES.items():
                    if name == "RSA-3072" and fmt == "expandida":
                        continue
                    rep, mig, ops = modelo(arq, s, fmt, phi)
                    d = np.median(rep - base)
                    print(f"{arq:4} {name:12} {fmt:9} {np.median(kib(rep)):16.1f} {mig.sum()/2**20:20.1f} {ops.sum():18,.0f} {kib(d):+21.1f} KiB")
        print()
