import email    #    lib principal - implementa o padrão RFC 5322
import os    #    interface com sistema operacional 
import json      #     JavaScript Object Notation - deixar padronizado
import re     #     lib de regex - pra extrair os IPs
import requests      #      http - lib padrão pra http -precisa de instalação externa - pip install requests
import hashlib      #     transforma qualquer quantidade de dados em uma string de tamanho fixo - mesma entrada gera a mesma saída
from datetime import datetime         #     timestamps precisos

def load_email(way_email):     #      define uma função que recebe uma string com o path do arquivo .eml
    with open('samples/  A R Q U I V O .eml', 'r', encoding='utf-8', errors='replace') as f:      #      abre o arquivo em modo leitura com o 'r' = read, utf-8 é o encoding
        # o errors='replace' evita que caia o script e troca byte que não é ut-8 pra "?"
        # "as f" significa que o arquivo é fechado automaticamente ao sair do bloco
        return email.message_from_file(f) # lê o objeto de arquivo aberto e retorna um objeto do tipo EmailMessage

def extract_header(msg):      #     define a função que extrai informações do cabeçalho
    campos = ['From', 'To', 'Subject', 'Date', 'Reply-To', 'Return-Path', 'Message-ID', 'X-Mailer']     #      lista com os campos relevantes do cabeçalho a serem extraídos
    result = {}     #     dicionário acumulador de resultados - será preenchido no loop abaixo
    for campo in campos:     #      itera sobre cada campo da lista acima
        valor = msg.get(campo, 'Não encontrado')     #      busca o valor do campo no cabeçalho; retorna 'Não encontrado' se ausente
        result[campo] = valor      #      armazena o par campo:valor no dicionário de resultados
    result['Received'] = msg.get_all('Received', [])     #    busca TODOS os cabeçalhos 'Received' como lista (um e-mail pode ter vários)
    return result    #     retorna o dicionário completo com todos os campos extraídos

def extract_ips(received_headers):    #    função que extrai IPs públicos a partir dos cabeçalhos Received
    default_ip = re.compile(    #    compila a regex que identifica endereços IPv4 válidos (0.0.0.0 a 255.255.255.255)
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'    #    valida os três primeiros octetos do IP
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'     #    valida o quarto octeto e delimita a palavra com \b
    )
    ips = set()    #    usa set para evitar IPs duplicados automaticamente
    for header in received_headers:    #    itera sobre cada cabeçalho Received
        found = default_ip.findall(header)    #    aplica a regex e retorna lista de todos os IPs encontrados no cabeçalho
        for ip in found:      #     itera sobre os IPs encontrados no cabeçalho atual
            if not (ip.startswith('192.168') or     #    filtra IPs privados da faixa 192.168.x.x (RFC 1918)
                    ip.startswith('10.') or          #     filtra IPs privados da faixa 10.x.x.x (RFC 1918)
                    ip.startswith('127.') or          #     filtra loopback (localhost)
                    ip.startswith('172.')):          #     filtra IPs privados da faixa 172.16-31.x.x (RFC 1918)
                ips.add(ip)      #     adiciona ao set somente IPs públicos (não privados)
    return list(ips)     #     converte o set em lista para facilitar a iteração posterior

def geolocalize_ip(ip):    #     função que consulta a API ip-api.com para obter a geolocalização de um IP
    try:
        resp = requests.get(     #     realiza requisição HTTP GET para a API pública de geolocalização
            f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org',     #    URL com o IP e os campos desejados na resposta
            timeout=5     #    define timeout de 5 segundos para evitar que o script trave em caso de rede lenta
        )
        return resp.json()     #    converte a resposta JSON da API em dicionário Python e retorna
    except:
        return {'erro': 'Sem rede ou timeout'}    #      captura qualquer exceção (timeout, sem conexão) e retorna erro amigável

def extract_supplements(msg):      #      função que percorre as partes do e-mail em busca de anexos
    supplements = []     #      lista que acumulará os metadados de cada anexo encontrado

    for parts in msg.walk():      #     walk() percorre recursivamente todas as partes MIME do e-mail
        if parts.get_content_maintype() == 'multipart':      #     ignora partes do tipo multipart (são contêineres, não arquivos)
            continue
        if parts.get('Dontent-Disposition') is None:     #    verifica o Content-Disposition; se ausente, não é um anexo
            continue

        name_file = parts.get_filename()     #     tenta obter o nome do arquivo do anexo
        if not name_file:      #    se não há nome de arquivo, não é um anexo real - pula
            continue

        data = parts.get_payload(decode=True)     #     decodifica o payload do anexo (base64/quoted-printable) para bytes brutos

        if data:    #     processa apenas se há dados válidos no payload
            info_file = {
                'name': name_file,     #      nome original do arquivo anexado
                'extension': os.path.splitext(name_file)[1],     #     extrai a extensão do arquivo (ex: .pdf, .exe)
                'size': len(data),    #      tamanho do arquivo em bytes
                'md5': hashlib.md5(data).hexdigest(),     #     hash MD5 do arquivo - útil para comparação rápida
                'sha256': hashlib.sha256(data).hexdigest(),     #     hash SHA256 do arquivo - mais seguro, usado em threat intelligence
                'magic_bytes': data[:4].hex(),     #      primeiros 4 bytes em hex - identifica o tipo real do arquivo
                'real_type': detect_type(data[:4])    #    chama detect_type para interpretar o tipo real pelo magic bytes
            }
            supplements.append(info_file)     #     adiciona o dicionário com metadados do anexo na lista
    return supplements      #    retorna a lista com todos os anexos encontrados e seus metadados

def detect_type(magic):    #    função que identifica o tipo real de um arquivo pelos seus magic bytes (assinatura binária)
    table = {
        b'\x50\x4B\x03\x04': 'ZIP / DOCX / XLSX / APKG',    #    ZIP header - também usado por formatos Office modernos e APKG
        b'\x25\x50\x44\x46': 'PDF',            #    %PDF - assinatura padrão de arquivos PDF
        b'\x4D\x5A': 'EXE / DLL (Windows PE)',     #    MZ - cabeçalho do formato Portable Executable do Windows
        b'\xFF\xD8\xFF': 'JPEG',               #     assinatura padrão de imagens JPEG/JPG
        b'\x89\x50\x4E\x47': 'PNG',           #     .PNG - assinatura padrão de imagens PNG
        b'\xD0\xCF\x11\xE0': 'DOC / XLS antigo (OLE)',    #    OLE2 Compound Document - formato Office legado (.doc, .xls)
    }
    for signature, type in table.items():    #    itera sobre cada assinatura conhecida na tabela
        if magic[:len(signature)] == signature:    #    compara os primeiros bytes do arquivo com a assinatura
            return type    #     retorna o tipo correspondente se houver match
    return 'Unknown'    #      retorna 'Unknown' se nenhuma assinatura for reconhecida

def analyze_email(way_email):     #     função principal que orquestra toda a análise do e-mail
    print(f"\n Iniciando análise: {way_email}")    #     exibe no terminal o arquivo que está sendo analisado

    msg = load_email(way_email)     #    carrega e parseia o arquivo .eml em um objeto EmailMessage
    header = extract_header(msg)     #     extrai os campos relevantes do cabeçalho como dicionário
    public_ips = extract_ips(header.get('Received', []))     #     extrai os IPs públicos dos cabeçalhos Received
    supplements = extract_supplements(msg)      #      extrai metadados de todos os anexos presentes no e-mail

    geo_ips = {}      #       dicionário que armazenará os dados de geolocalização de cada IP público
    for ip in public_ips:     #     itera sobre cada IP público encontrado
        print(f"  Geolocalizating IP: {ip}")     #     exibe o IP sendo consultado
        geo_ips[ip] = geolocalize_ip(ip)     #     consulta a geolocalização e armazena no dicionário

    relatorio = {
        'timestamp_analyze': datetime.now().isoformat(),      #      data e hora exata da análise no formato ISO 8601
        'file_analyzed': os.path.basename(way_email),      #      apenas o nome do arquivo, sem o caminho completo
        'header': header,     #      dicionário com os campos do cabeçalho extraídos
        'detected_ips': geo_ips,     #     dicionário com IPs e suas respectivas geolocalizações
        'supplements': supplements,     #      lista com metadados dos anexos encontrados
        'notifications': init_notifications(header, supplements)     #    lista de alertas gerados pela análise
    }

    os.makedirs('reports', exist_ok=True)      #    cria o diretório 'reports' se não existir; exist_ok=True evita erro se já existir
    exit_name = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"    #     monta o nome do arquivo de saída com timestamp
    with open(exit_name, 'w', encoding='utf-8') as f:     #      abre o arquivo de relatório em modo escrita
        json.dump(relatorio, f, indent=4, ensure_ascii=False)     #     serializa o dicionário como JSON formatado; ensure_ascii=False preserva acentos

    print(f"  Report saved: {exit_name}")    #      exibe o caminho do relatório salvo
    return relatorio     #     retorna o dicionário do relatório para uso programático

def init_notifications(header, supplement):    #     função que analisa o e-mail e gera alertas de segurança
    notifications = []    #    lista que acumulará os alertas encontrados
    mail_from = header.get('From', '')    #    obtém o remetente do cabeçalho From
    reply_to = header.get('Reply-To', 'NOT FOUND')    #    obtém o Reply-To; 'NOT FOUND' como padrão se ausente

    if reply_to != 'NOT FOUND' and reply_to != mail_from:    #    verifica se Reply-To existe E é diferente do From - indício de spoofing
        notifications.append({
            'level: ': 'HIGH',    #    nível de severidade do alerta
            'description: ': f'Reply-To different from From - Possible Spoofing',     #    descrição do problema detectado
            'detail: ': f'From: {mail_from} | Replay-To: {reply_to}'     #    detalhe com os valores divergentes para investigação
        })

    for supplement in supplement:     #    itera sobre cada anexo extraído
        if supplement['real_type'] in ['EXE / DLL (Windows PE)', 'ZIP / DOCX / XLSX / APKG']:     #    verifica se o tipo real é potencialmente malicioso
            notifications.append({ 
                'level': 'CRITIC',      #    nível crítico para anexos executáveis ou compactados suspeitos
                'description': f'Supplement suspicious detected: {supplement["name"]}',     #    nome do arquivo suspeito
                'detail': f'Real type: {supplement["real_type"]} | SHA256: {supplement["sha256"]}'    #    tipo real e hash para threat intelligence
            })

    return notifications     #    retorna a lista de alertas gerados

if __name__ == '__main__':    #     bloco executado apenas quando o script é rodado diretamente (não ao ser importado como módulo)
    analyze_email('samples/ A R Q U I V O .eml ')    #    inicia a análise do arquivo de e-mail de teste