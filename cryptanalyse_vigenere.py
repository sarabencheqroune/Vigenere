# Sorbonne Université 3I024 2024-2025
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : BENCHEQROUNE SARA

import sys, getopt, string, math

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Fréquence moyenne des lettres en français
# À modifier
freq_FR = [0.08167, 0.009, 0.034, 0.036, 0.171, 0.010, 0.0087, 0.0074, 0.075, 0.0061,
           0.00049, 0.054, 0.029, 0.071, 0.052, 0.030, 0.0095, 0.068, 0.080, 0.072,
           0.063, 0.018, 0.0011, 0.0043, 0.003, 0.001]

# Chiffrement César
def chiffre_cesar(txt, key):
    result = ''
    for c in txt:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            decale = (ord(c) - base + key) % 26
            result += chr(decale + base)
        else:
            result += c
    return result

# Déchiffrement César
def dechiffre_cesar(txt, key):
    
    return chiffre_cesar(txt, -key)

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    res = ""
    for i in range(len(txt)):
        c = txt[i]
        if c in alphabet:
            d = key[i % len(key)]
            idx = alphabet.index(c)
            res += alphabet[(idx + d) % len(alphabet)]
        else:
            res += c
    return res

   
# Déchiffrement Vigenere
def chiffre_vigenere(txt, key_str):
    key = [(ord(c.upper()) - ord('A')) for c in key_str]
    res = ""
    for i in range(len(txt)):
        c = txt[i]
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            decale = key[i % len(key)]
            res += chr((ord(c) - base + decale) % 26 + base)
        else:
            res += c
    return res

# Analyse de fréquences

def freq(txt):
    hist = [0] * len(alphabet)
    for c in txt:
        if c in alphabet:
            hist[alphabet.index(c)] += 1
    return hist


def lettre_freq_max(txt):
    hist = freq(txt)
    return hist.index(max(hist))

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
    
    hist = freq(txt)
    return hist.index(max(hist))

assert freq(alphabet) == [1] * 26

# indice de coïncidence
def indice_coincidence(hist):
    
    total = sum(hist)
    if total == 0:
        return 0.0
    ic = sum([f * (f - 1) for f in hist])
    return ic / (total * (total - 1)) if total > 1 else 0.0

def longueur_clef(cipher):
    
    best_k = 1
    best_ic = 0.0
    for k in range(1, 21):
        ic_moyen = 0.0
        for i in range(k):
            colonne = cipher[i::k]
            hist = [colonne.count(c) for c in alphabet]
            ic_moyen += indice_coincidence(hist)
        ic_moyen /= k
        if ic_moyen > best_ic:
            best_ic = ic_moyen
            best_k = k
    return best_k

# Recherche la longueur de la clé
def longueur_clef(cipher):
    
    best_k = 1
    best_ic = 0.0
    for k in range(1, 21):
        ic_moyen = 0.0
        for i in range(k):
            colonne = cipher[i::k]
            hist = [colonne.count(c) for c in alphabet]
            ic_moyen += indice_coincidence(hist)
        ic_moyen /= k
        if ic_moyen > best_ic:
            best_ic = ic_moyen
            best_k = k
    return best_k

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    
    decalages = [0] * key_length
    for i in range(key_length):
        colonne = cipher[i::key_length]
        max_letter = lettre_freq_max(colonne)
        decalages[i] = (max_letter - alphabet.index('E')) % 26

    return decalages


# Cryptanalyse V1 avec décalages par frequence max

def cryptanalyse_v1(cipher):
   
    key_length = longueur_clef(cipher)
    decalages = clef_par_decalages(cipher, key_length)
    txt = ""
    for i, c in enumerate(cipher):
        if c in alphabet:
            idx = (alphabet.index(c) - decalages[i % key_length]) % 26
            txt += alphabet[idx]
        else:
            txt += c

    return txt

################################################################

### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1, h2, d):
    
    return sum([h1[i] * h2[(i + d) % 26] for i in range(26)])

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):

    decalages = [0] * key_length
    ref_col = cipher[0::key_length]
    ref_hist = freq(ref_col)
    for i in range(1, key_length):
        col = cipher[i::key_length]
        hist_col = freq(col)
        best_icm = -1
        best_d = 0
        for d in range(26):
            icm = indice_coincidence_mutuelle(ref_hist, hist_col, d)
            if icm > best_icm:
                best_icm = icm
                best_d = d
        decalages[i] = best_d

    return decalages

# Cryptanalyse V2 avec décalages par ICM
def cryptanalyse_v2(cipher):

    key_length = longueur_clef(cipher)
    decalages = tableau_decalages_ICM(cipher, key_length)
    txt = ""
    for i, c in enumerate(cipher):
        if c in alphabet:
            idx = (alphabet.index(c) - decalages[i % key_length]) % 26
            txt += alphabet[idx]
        else:
            txt += c
    return txt

################################################################

### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def correlation(x, y):
    # Vérifie que les deux listes ont la même longueur
    if len(x) != len(y):
        raise ValueError("Les listes doivent avoir la même longueur")

    # Calcul des moyennes des listes
    mean_x = sum(x) / len(x)
    mean_y = sum(y) / len(y)

    # Calcul des termes nécessaires à la corrélation
    numerator = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(len(x)))
    denominator = math.sqrt(sum((x[i] - mean_x) ** 2 for i in range(len(x))) * sum((y[i] - mean_y) ** 2 for i in range(len(y))))

    # Calcul de la corrélation
    return numerator / denominator

# Test
result = correlation([1, 2, 3, 4], [2, 4, 6, 8])
print(result)

# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):

    key = [0] * key_length
    score_total = 0.0
    for i in range(key_length):
        best_corr = -1
        best_d = 0
        col = cipher[i::key_length]
        hist_col = freq(col)
        for d in range(26):
            rotated = hist_col[d:] + hist_col[:d]
            corr = correlation(rotated, freq_FR)
            if corr > best_corr:
                best_corr = corr
                best_d = d
        key[i] = best_d
        score_total += best_corr
    score = score_total / key_length

    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    
    best_score = -1
    best_key = []
    for key_length in range(1, 21):
        score, key = clef_correlations(cipher, key_length)
        if score > best_score:
            best_score = score
            best_key = key
    txt = ""
    for i, c in enumerate(cipher):
        if c in alphabet:
            idx = (alphabet.index(c) - best_key[i % len(best_key)]) % 26
            txt += alphabet[idx]
        else:
            txt += c

    return txt


################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])

