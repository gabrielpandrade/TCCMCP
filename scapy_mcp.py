import asyncio
import ipaddress
import whois
from concurrent.futures import ThreadPoolExecutor

from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.l2 import ARP, Ether
import scapy.config
scapy.config.conf.verb = 0

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("scapy-mcp")

@mcp.tool(name="ping_sweep", description="Descoberta de hosts ativos em uma faixa de IPs usando ICMP ping")
async def ping_sweep(network: str, timeout: int = 1) -> str:

    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        return f"Erro: Rede inválida '{network}'. Use formato CIDR (ex: 192.168.1.0/24)"
    
    # Limitar o número de hosts para evitar scans muito grandes
    if net.num_addresses > 256:
        return f"Erro: Rede muito grande ({net.num_addresses} hosts). Use uma rede menor (/24 ou maior)."
    
    active_hosts = []
    total_hosts = net.num_addresses

    def ping_host(ip_str):
        packet = IP(dst=ip_str)/ICMP()

        response = sr1(packet, timeout=timeout, verbose=0)
        
        if response and response.haslayer(ICMP):
            if response[ICMP].type == 0:
                return {
                    'ip': ip_str,
                    'status': 'ativo',
                    'ttl': response[IP].ttl,
                    'response_time': f"{response.time - packet.sent_time:.3f}s" if hasattr(packet, 'sent_time') else 'N/A'
                }

        
        return None
    
    loop = asyncio.get_event_loop()
    
    host_ips = [str(ip) for ip in net.hosts()] if net.num_addresses > 2 else [str(net.network_address)]
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [loop.run_in_executor(executor, ping_host, ip) for ip in host_ips]
        results = await asyncio.gather(*futures)
    
    active_hosts = [result for result in results if result is not None]
    
    result_text = f"=== PING SWEEP RESULTS ===\n"
    result_text += f"Rede: {network}\n"
    result_text += f"Total de hosts testados: {len(host_ips)}\n"
    result_text += f"Hosts ativos encontrados: {len(active_hosts)}\n\n"
    
    if active_hosts:
        result_text += "HOSTS ATIVOS:\n"
        result_text += "-" * 50 + "\n"
        for host in active_hosts:
            result_text += f"IP: {host['ip']:<15} | TTL: {host['ttl']:<3} | Tempo: {host['response_time']}\n"
    else:
        result_text += "Nenhum host ativo encontrado.\n"
    
    result_text += "\n" + "=" * 50
    
    return result_text

@mcp.tool(name="port_scan", description="Descoberta de portas abertas usando TCP SYN scan")
async def port_scan(target: str, ports_str: str, timeout: int = 1) -> str:
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return f"Erro: Não foi possível resolver o hostname '{target}'"
    
    ports = []
    try:
        if '-' in ports_str:
            # Range de portas (ex: 1-1000)
            start, end = map(int, ports_str.split('-'))
            if start > end or start < 1 or end > 65535:
                return "Erro: Range de portas inválido. Use 1-65535."
            ports = list(range(start, end + 1))
        elif ',' in ports_str:
            # Lista de portas (ex: 80,443,22)
            ports = [int(p.strip()) for p in ports_str.split(',')]
        else:
            # Porta única
            ports = [int(ports_str)]
        
        for port in ports:
            if port < 1 or port > 65535:
                return f"Erro: Porta inválida {port}. Use portas entre 1-65535."
        
        if len(ports) > 1000:
            return f"Erro: Muitas portas para escanear ({len(ports)}). Limite: 1000 portas."
            
    except ValueError:
        return f"Erro: Formato de portas inválido '{ports_str}'. Use '80', '80,443,22' ou '1-1000'."
    
    def scan_port(port):
        try:
            syn_packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            
            # Enviar pacote e aguardar resposta
            response = sr1(syn_packet, timeout=timeout, verbose=0)
            
            if response:
                if response.haslayer(TCP):
                    tcp_layer = response[TCP]
                    if tcp_layer.flags == 18:  # SYN-ACK (0x12)
                        # Porta aberta - enviar RST para fechar conexão
                        rst_packet = IP(dst=target_ip)/TCP(dport=port, flags="R")
                        send(rst_packet, verbose=0)
                        
                        return {
                            'port': port,
                            'status': 'aberta',
                            'service': get_service_name(port)
                        }
                    elif tcp_layer.flags == 20: 
                        return {
                            'port': port,
                            'status': 'fechada',
                            'service': get_service_name(port)
                        }
                elif response.haslayer(ICMP):
                    icmp_layer = response[ICMP]
                    if icmp_layer.type == 3:
                        return {
                            'port': port,
                            'status': 'filtrada',
                            'service': get_service_name(port)
                        }
            
            return {
                'port': port,
                'status': 'filtrada/timeout',
                'service': get_service_name(port)
            }
            
        except Exception as e:
            return {
                'port': port,
                'status': 'erro',
                'service': get_service_name(port)
            }
    
    def get_service_name(port):
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL',
            1433: 'MSSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        return common_ports.get(port, 'Unknown')
    
    loop = asyncio.get_event_loop()
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [loop.run_in_executor(executor, scan_port, port) for port in ports]
        results = await asyncio.gather(*futures)
    
    open_ports = [r for r in results if r['status'] == 'aberta']
    closed_ports = [r for r in results if r['status'] == 'fechada']
    filtered_ports = [r for r in results if 'filtrada' in r['status']]
    error_ports = [r for r in results if r['status'] == 'erro']
    
    result_text = f"=== PORT SCAN RESULTS ===\n"
    result_text += f"Alvo: {target} ({target_ip})\n"
    result_text += f"Portas escaneadas: {len(ports)}\n"
    result_text += f"Timeout: {timeout}s\n\n"
    
    if open_ports:
        result_text += f"PORTAS ABERTAS ({len(open_ports)}):\n"
        result_text += "-" * 40 + "\n"
        for port_info in sorted(open_ports, key=lambda x: x['port']):
            result_text += f"  {port_info['port']:<6} | {port_info['service']}\n"
        result_text += "\n"
    
    if closed_ports and len(closed_ports) <= 20:
        result_text += f"PORTAS FECHADAS ({len(closed_ports)}):\n"
        result_text += "-" * 40 + "\n"
        for port_info in sorted(closed_ports, key=lambda x: x['port']):
            result_text += f"  {port_info['port']:<6} | {port_info['service']}\n"
        result_text += "\n"
    elif closed_ports:
        result_text += f"PORTAS FECHADAS: {len(closed_ports)}\n\n"
    
    if filtered_ports and len(filtered_ports) <= 20:
        result_text += f"PORTAS FILTRADAS ({len(filtered_ports)}):\n"
        result_text += "-" * 40 + "\n"
        for port_info in sorted(filtered_ports, key=lambda x: x['port']):
            result_text += f"  {port_info['port']:<6} | {port_info['service']}\n"
        result_text += "\n"
    elif filtered_ports:
        result_text += f"PORTAS FILTRADAS: {len(filtered_ports)}\n\n"
    
    if error_ports:
        result_text += f"ERROS: {len(error_ports)} portas\n\n"
    
    result_text += "RESUMO:\n"
    result_text += f"  Abertas: {len(open_ports)}\n"
    result_text += f"  Fechadas: {len(closed_ports)}\n"
    result_text += f"  Filtradas: {len(filtered_ports)}\n"
    result_text += f"  Erros: {len(error_ports)}\n"
    
    result_text += "\n" + "=" * 50
    
    return result_text

async def arp_scan(network: str) -> str:
    """Implementação do ARP scan para descobrir dispositivos na rede local"""
    try:
        # Validar rede CIDR
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            return f"Erro: Rede inválida '{network}'. Use formato CIDR (ex: 192.168.1.0/24)"
        
        # Limitar o número de hosts para evitar scans muito grandes
        if net.num_addresses > 256:
            return f"Erro: Rede muito grande ({net.num_addresses} hosts). Use uma rede menor (/24 ou maior)."
        
        def arp_scan_host(ip_str):
            """Função para fazer ARP scan em um host específico"""
            try:
                # Criar pacote ARP request
                arp_request = ARP(pdst=ip_str)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request
                
                # Enviar pacote e aguardar resposta
                answered_list = srp(arp_request_broadcast, timeout=1, verbose=0)[0]
                
                devices = []
                for element in answered_list:
                    device_info = {
                        'ip': element[1].psrc,
                        'mac': element[1].hwsrc,
                        'vendor': 'Unknown'
                    }
                    
                    # Tentar obter informações do vendor via OUI
                    try:
                        # Scapy tem uma função para resolver OUI
                        from scapy.layers.l2 import get_if_hwaddr
                        import scapy.data
                        
                        # Extrair OUI (primeiros 3 bytes do MAC)
                        oui = element[1].hwsrc[:8].upper().replace(':', '')
                        
                        # Tentar buscar no banco de dados OUI do Scapy
                        if hasattr(scapy.data, 'OUI'):
                            vendor = scapy.data.OUI.get(oui, 'Unknown')
                            device_info['vendor'] = vendor
                    except Exception as e:
                        pass
                    
                    devices.append(device_info)
                
                return devices
                
            except Exception as e:
                return []
        
        # Executar ARP scan usando ThreadPoolExecutor
        loop = asyncio.get_event_loop()
        
        # Para ARP scan, é mais eficiente fazer um broadcast para toda a rede
        # ao invés de host por host
        try:
            # Criar pacote ARP request para toda a rede
            arp_request = ARP(pdst=str(network))
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Executar em thread separada para não bloquear
            def do_arp_scan():
                answered_list = srp(arp_request_broadcast, timeout=2, verbose=0)[0]
                devices = []
                
                for element in answered_list:
                    device_info = {
                        'ip': element[1].psrc,
                        'mac': element[1].hwsrc,
                        'vendor': 'Unknown'
                    }
                    
                    # Tentar obter informações do vendor
                    try:
                        # Extrair OUI (primeiros 3 bytes do MAC)
                        mac_oui = element[1].hwsrc[:8].upper().replace(':', '')
                        
                        # Lista básica de vendors conhecidos
                        oui_vendors = {
                            '00:50:56': 'VMware',
                            '08:00:27': 'VirtualBox',
                            '00:0C:29': 'VMware',
                            '00:1C:42': 'Parallels',
                            '52:54:00': 'QEMU/KVM',
                            '00:16:3E': 'Xen',
                            'B8:27:EB': 'Raspberry Pi Foundation',
                            'DC:A6:32': 'Raspberry Pi Foundation',
                            'E4:5F:01': 'Raspberry Pi Foundation',
                            '00:1B:44': 'Cisco',
                            '00:1E:58': 'Cisco',
                            '00:26:99': 'Cisco',
                            '3C:5A:B4': 'Google',
                            '00:1A:11': 'Google',
                            '00:50:C2': 'IEEE Registration Authority',
                            '00:E0:4C': 'Realtek',
                            '52:54:00': 'Red Hat',
                            '00:15:5D': 'Microsoft',
                            '00:03:FF': 'Microsoft'
                        }
                        
                        vendor = oui_vendors.get(mac_oui, 'Unknown')
                        device_info['vendor'] = vendor
                        
                    except Exception as e:
                        pass
                    
                    devices.append(device_info)
                
                return devices
            
            # Executar ARP scan
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = loop.run_in_executor(executor, do_arp_scan)
                devices = await future
            
            # Formatar resultado
            result_text = f"=== ARP SCAN RESULTS ===\n"
            result_text += f"Rede: {network}\n"
            result_text += f"Dispositivos encontrados: {len(devices)}\n\n"
            
            if devices:
                result_text += "DISPOSITIVOS ATIVOS:\n"
                result_text += "-" * 70 + "\n"
                result_text += f"{'IP':<15} | {'MAC Address':<17} | {'Vendor'}\n"
                result_text += "-" * 70 + "\n"
                
                for device in devices:
                    result_text += f"{device['ip']:<15} | {device['mac']:<17} | {device['vendor']}\n"
            else:
                result_text += "Nenhum dispositivo encontrado na rede.\n"
            
            result_text += "\n" + "=" * 70
            
            return result_text
            
        except Exception as e:
            return f"Erro ao executar ARP scan: {str(e)}"
        
    except Exception as e:
        return f"Erro ao executar ARP scan: {str(e)}"

async def os_fingerprint(self, args: Dict[str, Any]) -> str:
    """Implementação do OS fingerprinting simples"""
    try:
        target = args.get("target")
        
        # Resolver hostname para IP se necessário
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            return f"Erro: Não foi possível resolver o hostname '{target}'"
        
        def fingerprint_os():
            """Função para fazer OS fingerprinting"""
            try:
                fingerprint_data = {
                    'ttl_values': [],
                    'window_sizes': [],
                    'tcp_options': [],
                    'icmp_responses': [],
                    'tcp_flags': []
                }
                
                # Teste 1: ICMP Echo Request para obter TTL
                icmp_packet = IP(dst=target_ip)/ICMP()
                icmp_response = sr1(icmp_packet, timeout=2, verbose=0)
                
                if icmp_response and icmp_response.haslayer(IP):
                    ttl = icmp_response[IP].ttl
                    fingerprint_data['ttl_values'].append(('ICMP', ttl))
                
                # Teste 2: TCP SYN para portas comuns para obter características TCP
                common_ports = [80, 443, 22, 21, 25, 53]
                
                for port in common_ports:
                    try:
                        # TCP SYN com opções específicas
                        tcp_packet = IP(dst=target_ip)/TCP(
                            dport=port, 
                            flags="S",
                            options=[('MSS', 1460), ('WScale', 7), ('Timestamp', (0, 0)), ('NOP', None), ('NOP', None)]
                        )
                        
                        tcp_response = sr1(tcp_packet, timeout=1, verbose=0)
                        
                        if tcp_response and tcp_response.haslayer(TCP):
                            tcp_layer = tcp_response[TCP]
                            
                            # Coletar TTL
                            if tcp_response.haslayer(IP):
                                ttl = tcp_response[IP].ttl
                                fingerprint_data['ttl_values'].append(('TCP', ttl))
                            
                            # Coletar window size
                            window = tcp_layer.window
                            fingerprint_data['window_sizes'].append(window)
                            
                            # Coletar TCP options
                            if hasattr(tcp_layer, 'options') and tcp_layer.options:
                                fingerprint_data['tcp_options'].extend(tcp_layer.options)
                            
                            # Coletar flags
                            fingerprint_data['tcp_flags'].append(tcp_layer.flags)
                            
                            # Se encontrou uma porta aberta, não precisa testar todas
                            if tcp_layer.flags == 18:  # SYN-ACK
                                # Enviar RST para fechar
                                rst_packet = IP(dst=target_ip)/TCP(dport=port, flags="R")
                                send(rst_packet, verbose=0)
                                break
                                
                    except Exception as e:
                        continue
                
                # Teste 3: TCP com flags inválidas
                try:
                    # TCP FIN scan (pode revelar comportamentos específicos do OS)
                    fin_packet = IP(dst=target_ip)/TCP(dport=80, flags="F")
                    fin_response = sr1(fin_packet, timeout=1, verbose=0)
                    
                    if fin_response:
                        fingerprint_data['tcp_flags'].append(('FIN_response', fin_response[TCP].flags if fin_response.haslayer(TCP) else 'ICMP'))
                except:
                    pass
                
                return fingerprint_data
                
            except Exception as e:
                return None
        
        def analyze_fingerprint(data):
            """Analisar dados coletados e tentar identificar o OS"""
            if not data:
                return "Não foi possível coletar dados suficientes para fingerprinting"
            
            os_hints = []
            confidence = 0
            
            # Análise de TTL
            ttl_values = [ttl for _, ttl in data['ttl_values']]
            if ttl_values:
                avg_ttl = sum(ttl_values) / len(ttl_values)
                
                if 60 <= avg_ttl <= 64:
                    os_hints.append("Linux/Unix (TTL ~64)")
                    confidence += 30
                elif 120 <= avg_ttl <= 128:
                    os_hints.append("Windows (TTL ~128)")
                    confidence += 30
                elif 250 <= avg_ttl <= 255:
                    os_hints.append("Cisco/Network Device (TTL ~255)")
                    confidence += 25
                elif 30 <= avg_ttl <= 32:
                    os_hints.append("Older Unix/Linux (TTL ~32)")
                    confidence += 20
            
            # Análise de Window Size
            if data['window_sizes']:
                unique_windows = set(data['window_sizes'])
                
                if 65535 in unique_windows:
                    os_hints.append("Possível Windows (Window Size 65535)")
                    confidence += 15
                elif any(w in [5840, 5792, 14600] for w in unique_windows):
                    os_hints.append("Possível Linux (Window Sizes típicos)")
                    confidence += 15
            
            # Análise de TCP Options
            if data['tcp_options']:
                option_types = [opt[0] if isinstance(opt, tuple) else opt for opt in data['tcp_options']]
                
                if 'Timestamp' in option_types:
                    os_hints.append("Suporte a TCP Timestamps (comum em sistemas modernos)")
                    confidence += 10
                
                if 'WScale' in option_types:
                    os_hints.append("Suporte a Window Scaling (sistemas modernos)")
                    confidence += 10
            
            return os_hints, confidence
        
        # Executar fingerprinting
        loop = asyncio.get_event_loop()
        
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = loop.run_in_executor(executor, fingerprint_os)
            fingerprint_data = await future
        
        # Analisar resultados
        os_hints, confidence = analyze_fingerprint(fingerprint_data)
        
        # Formatar resultado
        result_text = f"=== OS FINGERPRINTING RESULTS ===\n"
        result_text += f"Alvo: {target} ({target_ip})\n"
        result_text += f"Confiança: {confidence}%\n\n"
        
        if fingerprint_data:
            # Dados coletados
            result_text += "DADOS COLETADOS:\n"
            result_text += "-" * 40 + "\n"
            
            if fingerprint_data['ttl_values']:
                ttl_str = ", ".join([f"{proto}:{ttl}" for proto, ttl in fingerprint_data['ttl_values']])
                result_text += f"TTL Values: {ttl_str}\n"
            
            if fingerprint_data['window_sizes']:
                windows = list(set(fingerprint_data['window_sizes']))
                result_text += f"TCP Window Sizes: {', '.join(map(str, windows))}\n"
            
            if fingerprint_data['tcp_options']:
                options = list(set([opt[0] if isinstance(opt, tuple) else str(opt) for opt in fingerprint_data['tcp_options']]))
                result_text += f"TCP Options: {', '.join(options)}\n"
            
            result_text += "\n"
        
        # Análise e sugestões
        if os_hints:
            result_text += "ANÁLISE DO SISTEMA OPERACIONAL:\n"
            result_text += "-" * 40 + "\n"
            for hint in os_hints:
                result_text += f"• {hint}\n"
            
            result_text += "\n"
            
            if confidence >= 50:
                result_text += "🎯 ALTA CONFIANÇA - Identificação provável\n"
            elif confidence >= 30:
                result_text += "⚠️  MÉDIA CONFIANÇA - Identificação possível\n"
            else:
                result_text += "❓ BAIXA CONFIANÇA - Dados insuficientes\n"
        else:
            result_text += "❌ Não foi possível identificar o sistema operacional\n"
            result_text += "Possíveis causas:\n"
            result_text += "• Host não responde a pacotes de teste\n"
            result_text += "• Firewall bloqueando pacotes\n"
            result_text += "• Sistema com configurações não padrão\n"
        
        result_text += "\n" + "=" * 50
        
        return result_text
        
    except Exception as e:
        return f"Erro ao executar OS fingerprinting: {str(e)}"
    
@mcp.tool(name="whois_lookup", description="Realiza uma consulta WHOIS em um alvo e retorna informações relevantes")
async def whois_lookup(target: str) -> str:
    """
    Realiza uma consulta WHOIS em um alvo (domínio ou IP) e extrai informações relevantes.

    Args:
        target (str): O domínio ou endereço IP para o qual a consulta WHOIS será realizada.

    Returns:
        str: Uma string formatada com as informações WHOIS mais relevantes.
    """
    try:
        # Realiza a consulta WHOIS
        w = whois.whois(target)

        # Informações a serem extraídas
        relevant_info = {
            "Domain Name": w.domain_name,
            "Registrar": w.registrar,
            "Creation Date": w.creation_date,
            "Updated Date": w.updated_date,
            "Expiration Date": w.expiration_date,
            "Name Server": w.name_servers,
            "Organization": w.org,
            "Registrant Name": w.registrant_name,
            "Registrant Organization": w.registrant_organization,
            "Registrant Street": w.registrant_street,
            "Registrant City": w.registrant_city,
            "Registrant State/Province": w.registrant_state_province,
            "Registrant Postal Code": w.registrant_postal_code,
            "Registrant Country": w.registrant_country,
            "Registrant Phone": w.registrant_phone,
            "Registrant Email": w.registrant_email,
            "Admin Name": w.admin_name,
            "Admin Organization": w.admin_organization,
            "Admin Phone": w.admin_phone,
            "Admin Email": w.admin_email,
            "Tech Name": w.tech_name,
            "Tech Organization": w.tech_organization,
            "Tech Phone": w.tech_phone,
            "Tech Email": w.tech_email,
        }

        # Formata a saída
        result_text = f"=== WHOIS LOOKUP RESULTS FOR {target.upper()} ===\n"
        result_text += "-" * 50 + "\n"

        found_info = False
        for key, value in relevant_info.items():
            if value:
                found_info = True
                if isinstance(value, list):
                    result_text += f"{key}:\n"
                    for item in value:
                        result_text += f"  - {item}\n"
                else:
                    result_text += f"{key}: {value}\n"

        if not found_info:
            result_text += "Nenhuma informação relevante encontrada.\n"
            result_text += f"WHOIS completo (se disponível):\n{w}"

        result_text += "\n" + "=" * 50

        return result_text

    except whois.parser.WhoisCommandFailed as e:
        return f"Erro ao executar whois: {e}"
    except Exception as e:
        return f"Ocorreu um erro inesperado: {e}"
    

if __name__ == "__main__":
    mcp.run(transport="stdio")
    