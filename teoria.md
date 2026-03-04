# EML Analyzer

## Teoria
    Arquivo .eml
        Todo e-mail ao ser salvo vira um arquivo de texto puro no formato ".eml" - Padrão RFC 5322 - e tem 2 seções - Header e body
            
            CABEÇALHO (header)
            __________________________
            From: remetente@dominio.com
            To: destinatario@empresa.com
            Date: dia da semana, 0X Mês Ano Hora:minuto:segundo -GMT
            Subject: Assunto do e-mail
            Received: from mail.atacante.ru (IP: 911.911.911.9)
            DKIM-Signature: ...

            CORPO (body)
            __________________________
            Texto do e-mail aqui, pode ser HTML ou texto puro.
            Anexos são codificados em Base64 abaixo.

    O campo mais importante para a investigação é o "Received".
        Aparece múltiplas vezes e funciona como um carimbo
            Cada servidor de e-mail que a mensagem passou adiciona sua linha "Received"
            De baixo pra cima encontra a origem real do e-amil.
    
    Forjar o campo "From" é facil e isso é chamado de spoofing, mas não consegue forjar o campo received.

## SPF DKIM e DMARC
    ### SPF
        SE O SERVIDOR QUE ENVIOU ESTÁ AUTORIZADO PELO DOMINIO
            COMPARA IP DE ENVIO COM LISTA DO DNS DO DOMÍNIO
    ### DKIM
        SE O CONTEÚDO NÃO FOI ALTERADO NO CAMINHO
            ASSINA O E-MAIL COM CHAVE PRIVADA
            RECEPTOR VALIDA COM CHAVE PÚBLICA DNS
    ### DMARC
        O QUE FAZER SE SPF E DKIM FALHAR
            POLÍTICA: QUARANTINE, REJECT OU NONE
    
    SE UM E-MAIL CHEGA COM SPF: FAIL OU DKIM: FAIL É REDFLAG BRUTAL

## ANEXOS e ENCODING BASE64
    Anexos no e-mail são codificados em Base64
        Um sistema que converte bytes binários em caracteres ASCII para que possam ser transportados como texto
            Quando analisar um ".eml" precisa decodificar esse Base64 para recuperar o arquivo original e só então calcular o hash para chegar