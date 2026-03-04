import email   #   lib principal - implementa o padrão RFC 5322
import os    #   interface com sistema operacional 
import json   #   JavaScript Object Notation - deixar padronizado
import re    #   lib de regex - pra extrair os IPs
import requests    #    http - lib padrão pra http -precisa de instalação externa - pip install requests
import hashlib    #   transforma qualquer quantidade de dados em uma string de tamanho fixo - mesma entrada gera a mesma saída
from datetime import datetime    #   timestamps precisos

def load_email(way_email):   #   define uma função que recebe uma string com o path do arquivo .eml
    with open('samples/teste.eml', 'r', encoding='utf-8', errors='replace') as f:   #   abre o arquivo em modo leitura com o 'r' = read, utf-8 é o encoding
                #    o errors='replace' evita que caia o script e troca byte que não é ut-8 pra "?"
                #    "as f" significa que o arquivo é fechado automaticamente ao sair do bloco
        return email.message_from_file(f)    #   lê o objeto de arquivo aberto e retorna um objeto
    
def extract_header(msg):    #   define a função que extrai informações do cabeçalho
    campos = ['From', 'To', 'Subject', 'Date', 'Reply-To', 'Return-Path', 'Message-ID', 'X-Mailer']   #    quais informações de quais campos do cabeçalho
    result = {}    #   acumilador de resultados
    for campo in campos:    #    
        valor = msg.get(campo, 'Não encontrado')
        result[campo] = valor
    result['Received'] = msg.get_all('Received', [])
    return result

def extract_ips(received_headers):
    default_ip = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    ips = set()
    for header in received_headers:
        found = default_ip.findall(header)
        for ip in found:
            if not (ip.startswith('192.168') or 
                    ip.startswith('10.') or 
                    ip.startswith('127.') or 
                    ip.startswith('172.')):
                ips.add(ip)
        return list(ips)

def geolocalize_ip(ip):
    try:
        resp = requests.get(
            f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org',
            timeout=5
        )
        return resp.json()
    except:
        return {'erro': 'Sem rede ou timeout'}

def extract_supplements(msg):
    supplements = []
    
    for parts in msg.walk():
        if parts.get_content_maintype() == 'multipart':
            continue
        if parts.get('Dontent-Disposition') is None:
            continue

        name_file = parts.get_filename()
        if not name_file: 
            continue
        
        data = parts.get_payload(decode=True)

        if data:
            info_file = {
                'name': name_file, 
                'extension': os.path.splitext(name_file)[1],
                'size': len(data),
                'md5': hashlib.md5(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest(),
                'magic_bytes': data[:4].hex(),
                'real_type': detect_type(data[:4])
            }
            supplements.append(info_file)
    return supplements

def detect_type(magic):
    table = {
         b'\x50\x4B\x03\x04': 'ZIP / DOCX / XLSX / APKG',  # ZIP header
        b'\x25\x50\x44\x46': 'PDF',
        b'\x4D\x5A':         'EXE / DLL (Windows PE)',
        b'\xFF\xD8\xFF':     'JPEG',
        b'\x89\x50\x4E\x47': 'PNG',
        b'\xD0\xCF\x11\xE0': 'DOC / XLS antigo (OLE)',
    }
    for signature, type in table.items():
        if magic[:len(signature)] == signature:
            return type
    return 'Unknown'

def analyze_email(way_email):
    print(f"\n Iniciando análise:  {way_email}")

    msg = load_email(way_email)
    header = extract_header(msg)
    public_ips = extract_ips(header.get('Received', []))
    supplements = extract_supplements(msg)

    geo_ips = {}
    for ip in public_ips:
        print(f" Geolocalizating IP: {ip}")
        geo_ips[ip] = geolocalize_ip(ip)
    relatorio = {
        'timestamp_analyze': datetime.now().isoformat(),
        'file_analyzed': os.path.basename(way_email),
        'header': header,
        'detected_ips': geo_ips,
        'supplements': supplements,
        'notifications': init_notifications(header, supplements)
    }
    
    os.makedirs('reports', exist_ok=True)
    exit_name=f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open (exit_name, 'w', encoding='utf-8') as f:
        json.dump(relatorio, f, indent=4, ensure_ascii=False)

    print(f" Report saved: {exit_name}")
    return relatorio

def init_notifications(header, supplement):
    notifications=[]
    mail_from = header.get('From', '')
    reply_to = header.get('Reply-To', 'NOT FOUND')

    if reply_to != 'NOT FOUND' and reply_to != mail_from:
        notifications.append({
            'level: ': 'HIGH',
            'description: ': f'Reply-To different from From - Possible Spoofing', 
            'detail: ': f'From: {mail_from} |  Replay-To: {reply_to}' 
        })

        for supplement in supplement:
            if supplement['real_type'] in ['EXE / DLL (Windows PE)', 'ZIP / DOCX / XLSX / APKG']:
                notifications.appened({
                    'level': 'CRITIC',
                    'description': f'Supplement suspicious detected: {supplement["name"]}', 
                    'detail': f'Real type: {supplement["real_type"]}  | SHA256: {supplement["sha256"]}'
                })

        return notifications 

if __name__ == '__main__':
    analyze_email('samples/teste.eml')