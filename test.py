from ipwhois import IPWhois

ip = "uepg.br"  # exemplo com Google DNS
obj = IPWhois(ip)

# Consulta RDAP (mais moderno e estruturado que WHOIS)
result = obj.lookup_whois()

print(result)
print("Bloco de endereçamento:", result.get("network", {}).get("cidr"))
print("Nome da rede:", result.get("network", {}).get("name"))
print("ASN:", result.get("asn"))
print("Organização:", result.get("asn_description"))