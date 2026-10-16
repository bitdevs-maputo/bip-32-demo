
"""
Demonstração educativa da BIP32 — carteiras Bitcoin HD.

O programa mostra:
1. Como criar uma chave-mestra a partir de uma seed.
2. Como separar a chave privada e o chain code.
3. Como calcular a chave pública usando secp256k1.
4. Como derivar uma chave filha não endurecida (non-hardened).
5. Como verificar que a derivação privada e pública
   produzem a mesma chave pública filha.

AVISO:
Este programa é educativo. Não o uses para guardar fundos reais.
"""

import hashlib
import hmac

from ecdsa import SECP256k1
from ecdsa.ellipticcurve import INFINITY, Point


# --------------------------------------------------
# 1. PARÂMETROS DA CURVA ELÍPTICA
# --------------------------------------------------

# G é o ponto gerador da curva secp256k1.
# A multiplicação de G por um número inteiro produz um ponto.
G = SECP256k1.generator

# n é a ordem do ponto gerador.
# As chaves privadas válidas estão entre 1 e n - 1.
N = SECP256k1.order


def mostrar_bytes(nome, valor):
    """Mostra os bytes em hexadecimal e o seu tamanho."""
    print(f"{nome}:")
    print(f"  Hexadecimal: {valor.hex()}")
    print(f"  Tamanho: {len(valor)} bytes\n")


def chave_publica_comprimida(ponto):
    """
    Converte um ponto da curva numa chave pública comprimida.

    Uma chave pública comprimida Bitcoin tem 33 bytes:
    - 1 byte inicial: 02 ou 03, conforme a paridade de y.
    - 32 bytes seguintes: coordenada x.
    """
    x = ponto.x()
    y = ponto.y()

    prefixo = b"\x02" if y % 2 == 0 else b"\x03"

    return prefixo + x.to_bytes(32, "big")


# --------------------------------------------------
# 2. CRIAR A CHAVE-MESTRA A PARTIR DA SEED
# --------------------------------------------------

def criar_chave_mestra(seed):
    """
    Recebe uma seed e calcula a chave-mestra BIP32.

    HMAC-SHA512 devolve 64 bytes:
    - primeiros 32 bytes: chave privada mestra (IL);
    - últimos 32 bytes: chain code (IR).
    """

    print("=" * 60)
    print("ETAPA 1 — CRIAR A CHAVE-MESTRA")
    print("=" * 60)

    mostrar_bytes("Seed de entrada", seed)

    # A chave usada no HMAC é o texto "Bitcoin seed".
    # A mensagem é a seed.
    resultado = hmac.new(
        key=b"Bitcoin seed",
        msg=seed,
        digestmod=hashlib.sha512,
    ).digest()

    # Separar o resultado em duas partes de 32 bytes.
    chave_privada = int.from_bytes(resultado[:32], "big")
    chain_code = resultado[32:]

    # A chave privada tem de ser um número válido na curva.
    if not 1 <= chave_privada < N:
        raise ValueError("A seed produziu uma chave-mestra inválida.")

    mostrar_bytes("Resultado HMAC-SHA512", resultado)
    mostrar_bytes("Chain code mestre", chain_code)

    print("Chave privada mestra:")
    print(f"  Decimal: {chave_privada}")
    print(f"  Hexadecimal: {chave_privada:064x}\n")

    return chave_privada, chain_code


# --------------------------------------------------
# 3. CALCULAR A CHAVE PÚBLICA
# --------------------------------------------------

def calcular_chave_publica(chave_privada):
    """
    Calcula a chave pública usando a multiplicação de pontos:

        K = k * G

    k = chave privada
    G = ponto gerador
    K = ponto da chave pública
    """

    print("=" * 60)
    print("ETAPA 2 — CALCULAR A CHAVE PÚBLICA")
    print("=" * 60)

    ponto_publico = chave_privada * G
    chave_publica = chave_publica_comprimida(ponto_publico)

    print("Operação matemática: K = k * G")
    print(f"Chave pública comprimida: {chave_publica.hex()}")
    print(f"Tamanho: {len(chave_publica)} bytes\n")

    return ponto_publico, chave_publica


# --------------------------------------------------
# 4. DERIVAR UMA CHAVE FILHA PRIVADA
# --------------------------------------------------

def derivar_filha_privada(chave_pai, chain_code_pai, indice):
    """
    Deriva uma chave filha privada não endurecida.

    Para esta derivação, o HMAC recebe:
        chave pública do pai + índice da filha

    O resultado contém:
        IL = valor usado para derivar a chave filha
        IR = novo chain code

    Fórmula:
        chave_filha = (IL + chave_pai) mod n
    """

    if not 0 <= indice < 2**31:
        raise ValueError(
            "Este exemplo aceita índices de 0 até 2**31 - 1."
        )

    print("=" * 60)
    print("ETAPA 3 — DERIVAR A CHAVE FILHA PRIVADA")
    print("=" * 60)

    # Obter a chave pública do pai.
    ponto_pai = chave_pai * G
    pub_pai = chave_publica_comprimida(ponto_pai)

    # Representar o índice com exatamente 4 bytes.
    indice_bytes = indice.to_bytes(4, "big")

    # Dados de entrada do HMAC para uma filha não endurecida.
    dados = pub_pai + indice_bytes

    mostrar_bytes("Chave pública do pai", pub_pai)
    mostrar_bytes("Índice da filha", indice_bytes)
    mostrar_bytes("Dados enviados ao HMAC", dados)

    # HMAC usa o chain code do pai como chave.
    resultado = hmac.new(
        key=chain_code_pai,
        msg=dados,
        digestmod=hashlib.sha512,
    ).digest()

    tweak = int.from_bytes(resultado[:32], "big")
    chain_code_filho = resultado[32:]

    if tweak >= N:
        raise ValueError("Derivação inválida: IL fora do intervalo.")

    # A chave privada filha resulta da soma modular.
    chave_filha = (tweak + chave_pai) % N

    if chave_filha == 0:
        raise ValueError("Derivação inválida: chave filha igual a zero.")

    print(f"Índice escolhido: {indice}")
    print(f"IL (tweak): {tweak:064x}")
    print(f"Chave filha privada: {chave_filha:064x}")
    print(f"Chain code filho: {chain_code_filho.hex()}\n")

    return chave_filha, chain_code_filho, tweak


# --------------------------------------------------
# 5. DERIVAR A MESMA FILHA USANDO SÓ A CHAVE PÚBLICA
# --------------------------------------------------

def derivar_filha_publica(pub_pai, chain_code_pai, indice):
    """
    Deriva a chave pública filha sem conhecer a chave privada do pai.

    Fórmula:
        K_filha = IL * G + K_pai

    Esta operação só funciona para índices não endurecidos.
    """

    if not 0 <= indice < 2**31:
        raise ValueError("O índice tem de ser não endurecido.")

    print("=" * 60)
    print("ETAPA 4 — DERIVAR A CHAVE FILHA PÚBLICA")
    print("=" * 60)

    indice_bytes = indice.to_bytes(4, "big")
    dados = pub_pai + indice_bytes

    resultado = hmac.new(
        key=chain_code_pai,
        msg=dados,
        digestmod=hashlib.sha512,
    ).digest()

    tweak = int.from_bytes(resultado[:32], "big")
    chain_code_filho = resultado[32:]

    if tweak >= N:
        raise ValueError("Derivação inválida: IL fora do intervalo.")

    # Reconstruir o ponto público do pai a partir da chave comprimida.
    x = int.from_bytes(pub_pai[1:], "big")

    # secp256k1: y² = x³ + 7 (mod p)
    p = SECP256k1.curve.p()
    y_quadrado = (pow(x, 3, p) + 7) % p

    # Para secp256k1, p % 4 == 3, permitindo esta raiz modular.
    y = pow(y_quadrado, (p + 1) // 4, p)

    # Escolher a coordenada y correta segundo o prefixo 02/03.
    if (y % 2 == 0) != (pub_pai[0] == 2):
        y = p - y

    ponto_pai = Point(SECP256k1.curve, x, y, N)

    # Calcular K_filha = IL * G + K_pai.
    ponto_filho = tweak * G + ponto_pai

    if ponto_filho == INFINITY:
        raise ValueError("Derivação inválida: ponto no infinito.")

    pub_filha = chave_publica_comprimida(ponto_filho)

    print(f"Índice escolhido: {indice}")
    print(f"Chave pública filha: {pub_filha.hex()}")
    print(f"Chain code filho: {chain_code_filho.hex()}\n")

    return pub_filha, chain_code_filho


# --------------------------------------------------
# 6. EXECUTAR A DEMONSTRAÇÃO
# --------------------------------------------------

def main():
    print("\nDEMONSTRAÇÃO EDUCATIVA DA BIP32")
    print("Não utilizar estas chaves para fundos reais.\n")

    # Seed fixa para que os resultados sejam reproduzíveis.
    # Não é uma seed de carteira real.
    seed = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
    )

    # Passo 1: criar a chave-mestra.
    chave_mestra, chain_code_mestre = criar_chave_mestra(seed)

    # Passo 2: calcular a chave pública mestra.
    ponto_mestre, pub_mestra = calcular_chave_publica(chave_mestra)

    # Passo 3: derivar a filha privada de índice 0.
    indice = 0
    chave_filha, chain_code_filho, tweak = derivar_filha_privada(
        chave_mestra,
        chain_code_mestre,
        indice,
    )

    # Passo 4: derivar a chave pública filha de duas formas:
    # (a) usando a chave privada filha;
    # (b) usando somente a chave pública do pai.
    _, pub_filha_privada = calcular_chave_publica(chave_filha)

    pub_filha_publica, chain_code_publico = derivar_filha_publica(
        pub_mestra,
        chain_code_mestre,
        indice,
    )

    # Passo 5: comparar os resultados.
    print("=" * 60)
    print("ETAPA 5 — VERIFICAR OS RESULTADOS")
    print("=" * 60)

    print(
        "As chaves públicas filhas são iguais?",
        pub_filha_privada == pub_filha_publica,
    )

    print(
        "Os chain codes filhos são iguais?",
        chain_code_filho == chain_code_publico,
    )

    print("\nConclusão:")
    print(
        "Uma chave pública filha não endurecida pode ser derivada "
        "a partir da chave pública do pai e do chain code, "
        "sem revelar a chave privada."
    )


if __name__ == "__main__":
    main()
