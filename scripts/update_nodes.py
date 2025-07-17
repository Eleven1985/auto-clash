import requests
import base64
import yaml
import os
import json
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime # 用于处理日期占位符

# --- 辅助函数：解码与解析 ---

def fetch_subscriptions(sub_file="subscriptions.txt"):
    """从文件中读取订阅链接，并处理日期占位符和失效标记"""
    subscriptions = []
    # 新增一个列表来存储带有失效标记的链接
    invalid_subscriptions = []
    script_dir = os.path.dirname(__file__)
    abs_sub_file_path = os.path.join(script_dir, '..', sub_file)
    if os.path.exists(abs_sub_file_path):
        with open(abs_sub_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: # 忽略空行
                    continue
                if line.startswith('#'): # 忽略注释行
                    invalid_subscriptions.append(line) # 可能是手动标记的失效链接
                    continue

                # 处理 {Ymd} 占位符
                if '{Ymd}' in line:
                    today = datetime.now()
                    line = line.replace('{Ymd}', today.strftime('%Y%m%d'))
                subscriptions.append(line)
    else:
        print(f"Error: Subscription file not found at {abs_sub_file_path}")
    return subscriptions, invalid_subscriptions # 返回有效订阅和失效订阅

def decode_base64_url(data):
    """解码 Base64 URL 安全字符串"""
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data).decode('utf-8')

# --- 协议解析函数 ---

def parse_ss_node(uri):
    """解析 Shadowsocks (SS) 节点"""
    try:
        parsed_uri = urlparse(uri)
        fragment = unquote(parsed_uri.fragment) if parsed_uri.fragment else None
        encoded_part = parsed_uri.netloc

        try:
            decoded_info = decode_base64_url(encoded_part)
            if '@' not in decoded_info:
                raise ValueError("Decoded SS info does not contain '@'")
            parts = decoded_info.split('@')
        except Exception:
            parts = encoded_part.split('@')
            if len(parts) != 2:
                 if parsed_uri.query:
                     raise ValueError("SS URI contains unsupported query parameters for standard parsing.")
                 else:
                    raise ValueError("Invalid SS URI format: missing method:password.")

        if len(parts) != 2:
            raise ValueError("Invalid SS URI format: incorrect parts count after splitting '@'")

        auth_info = parts[0]
        server_info = parts[1]

        if ':' not in auth_info:
             raise ValueError("Invalid SS URI format: method:password missing ':'")

        method, password = auth_info.split(':', 1)
        server, port_str = server_info.split(':')
        port = int(port_str)
        
        node = {
            'name': fragment if fragment else f"SS-{server}:{port}",
            'type': 'ss',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password,
        }
        return node
    except Exception as e:
        # print(f"Error parsing SS node '{uri}': {e}") # 简化日志
        return None

def parse_vmess_node(uri):
    """解析 V2Ray (VMess) 节点"""
    try:
        base64_config = uri[8:] # 移除 "vmess://"
        decoded_config_str = decode_base64_url(base64_config)
        config = json.loads(decoded_config_str)

        node = {
            'name': config.get('ps', f"VMess-{config.get('add')}:{config.get('port')}"),
            'type': 'vmess', 'server': config.get('add'), 'port': int(config.get('port')),
            'uuid': config.get('id'), 'alterId': int(config.get('aid', 0)),
            'cipher': config.get('scy', 'auto'), 'tls': config.get('tls', False),
            'skip-cert-verify': config.get('v', '') == '2' or config.get('verify_cert', False),
            'network': config.get('net', 'tcp'), 'ws-path': config.get('path', ''),
            'ws-headers': config.get('host', '')
        }
        return node
    except Exception as e:
        # print(f"Error parsing VMess node '{uri}': {e}") # 简化日志
        return None

def parse_vless_node(uri):
    """解析 VLESS 节点"""
    try:
        parsed_uri = urlparse(uri)
        uuid = parsed_uri.username
        server = parsed_uri.hostname
        port = parsed_uri.port
        name = unquote(parsed_uri.fragment) if parsed_uri.fragment else None
        if not (uuid and server and port): raise ValueError("Missing essential VLESS parameters")
        query_params = parse_qs(parsed_uri.query)
        node = {
            'name': name if name else f"VLESS-{server}:{port}",
            'type': 'vless', 'server': server, 'port': int(port),
            'uuid': uuid,
            'tls': query_params.get('security', [''])[0] == 'tls' or query_params.get('type', [''])[0] in ['ws', 'grpc'],
            'flow': query_params.get('flow', [''])[0],
            'network': query_params.get('type', ['tcp'])[0],
            'ws-path': query_params.get('path', [''])[0],
            'ws-headers': query_params.get('host', [''])[0],
            'grpc-service-name': query_params.get('serviceName', [''])[0],
            'sni': query_params.get('sni', [''])[0] or server,
            'alpn': query_params.get('alpn', [''])[0].split(',') if query_params.get('alpn', [''])[0] else [],
            'skip-cert-verify': query_params.get('fp', [''])[0] == 'false',
            'encryption': query_params.get('encryption', ['none'])[0]
        }
        for k in list(node.keys()):
            if not node[k] and k not in ['alterId', 'tls', 'skip-cert-verify', 'mptcp', 'tcp-fast-open']:
                node.pop(k)
        return node
    except Exception as e:
        # print(f"Error parsing VLESS node '{uri}': {e}") # 简化日志
        return None

def parse_trojan_node(uri):
    """解析 Trojan 节点"""
    try:
        parsed_uri = urlparse(uri)
        password = parsed_uri.username
        server = parsed_uri.hostname
        port = parsed_uri.port
        name = unquote(parsed_uri.fragment) if parsed_uri.fragment else None
        if not (password and server and port): raise ValueError("Missing essential Trojan parameters")
        node = {
            'name': name if name else f"Trojan-{server}:{port}",
            'type': 'trojan', 'server': server, 'port': int(port),
            'password': password, 'tls': True
        }
        query_params = parse_qs(parsed_uri.query)
        if 'sni' in query_params: node['sni'] = query_params['sni'][0]
        if 'alpn' in query_params: node['alpn'] = query_params['alpn'][0].split(',')
        return node
    except Exception as e:
        # print(f"Error parsing Trojan node '{uri}': {e}") # 简化日志
        return None

def parse_hysteria_node(uri):
    """解析 Hysteria 节点 (Hysteria1)"""
    try:
        parsed_uri = urlparse(uri)
        server = parsed_uri.hostname
        port = parsed_uri.port
        name = unquote(parsed_uri.fragment) if parsed_uri.fragment else None
        if not (server and port): raise ValueError("Missing essential Hysteria parameters")
        query_params = parse_qs(parsed_uri.query)
        node = {
            'name': name if name else f"Hysteria-{server}:{port}",
            'type': 'hysteria', 'server': server, 'port': int(port),
            'auth': query_params.get('auth', [''])[0],
            'up': int(query_params.get('up', ['100'])[0]),
            'down': int(query_params.get('down', ['100'])[0]),
            'alpn': query_params.get('alpn', ['h3'])[0].split(','),
            'tls': True, 'sni': query_params.get('peer', [''])[0] or server,
            'skip-cert-verify': query_params.get('insecure', ['0'])[0] == '1',
            'obfs': query_params.get('obfs', ['none'])[0],
            'obfs-password': query_params.get('obfsParam', [''])[0],
            'mptcp': query_params.get('mptcp', ['false'])[0].lower() == 'true',
        }
        if node['obfs'] == 'none': node.pop('obfs-password', None)
        return node
    except Exception as e:
        # print(f"Error parsing Hysteria node '{uri}': {e}") # 简化日志
        return None

def parse_hysteria2_node(uri):
    """解析 Hysteria2 节点"""
    try:
        parsed_uri = urlparse(uri)
        password = parsed_uri.username
        server = parsed_uri.hostname
        port = parsed_uri.port
        name = unquote(parsed_uri.fragment) if parsed_uri.fragment else None
        if not (password and server and port): raise ValueError("Missing essential Hysteria2 parameters")
        query_params = parse_qs(parsed_uri.query)
        node = {
            'name': name if name else f"Hysteria2-{server}:{port}",
            'type': 'hysteria2', 'server': server, 'port': int(port),
            'password': password, 'tls': True, 'sni': query_params.get('sni', [''])[0] or server,
            'alpn': query_params.get('alpn', ['h3'])[0].split(','),
            'obfs': query_params.get('obfs', ['none'])[0], 'obfs-password': query_params.get('obfs-password', [''])[0],
            'fast-open': query_params.get('fastopen', ['true'])[0].lower() == 'true',
            'skip-cert-verify': query_params.get('insecure', ['0'])[0] == '1',
        }
        if node['obfs'] == 'none': node.pop('obfs-password', None)
        return node
    except Exception as e:
        # print(f"Error parsing Hysteria2 node '{uri}': {e}") # 简化日志
        return None

def parse_tuic_node(uri):
    """解析 TUIC 节点"""
    try:
        parsed_uri = urlparse(uri)
        auth_info_str = parsed_uri.username
        server = parsed_uri.hostname
        port = parsed_uri.port
        name = unquote(parsed_uri.fragment) if parsed_uri.fragment else None
        if not (auth_info_str and server and port): raise ValueError("Missing essential TUIC parameters")
        uuid, password = auth_info_str.split(':', 1)
        query_params = parse_qs(parsed_uri.query)
        node = {
            'name': name if name else f"TUIC-{server}:{port}",
            'type': 'tuic', 'server': server, 'port': int(port),
            'uuid': uuid, 'password': password, 'tls': True,
            'sni': query_params.get('sni', [''])[0] or server,
            'alpn': query_params.get('alpn', ['h3'])[0].split(','),
            'udp-relay-mode': query_params.get('udp_relay_mode', ['quic'])[0],
            'congestion-controller': query_params.get('congestion_controller', ['bbr'])[0],
            'tcp-fast-open': query_params.get('tcp_fast_open', ['true'])[0].lower() == 'true',
            'skip-cert-verify': query_params.get('insecure', ['0'])[0] == '1',
        }
        return node
    except Exception as e:
        # print(f"Error parsing TUIC node '{uri}': {e}") # 简化日志
        return None

def parse_ssr_node(uri):
    """解析 ShadowsocksR (SSR) 节点"""
    try:
        base64_part = uri[6:].split('#')[0]
        decoded_params_str = decode_base64_url(base64_part)
        parts = decoded_params_str.split(':')
        if len(parts) < 6: raise ValueError("Invalid SSR URI format")
        server = parts[0]
        port = int(parts[1])
        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        password_obfparam_protoparam = parts[5]
        password_part, query_part = (password_obfparam_protoparam.split('/?', 1) + [''])[:2]
        password = decode_base64_url(password_part)
        obfparam = ''
        protoparam = ''
        if query_part:
            query_params = parse_qs(query_part)
            obfparam = decode_base64_url(query_params.get('obfparam', [''])[0])
            protoparam = decode_base64_url(query_params.get('protoparam', [''])[0])
        name = unquote(urlparse(uri).fragment) if urlparse(uri).fragment else None
        node = {
            'name': name if name else f"SSR-{server}:{port}",
            'type': 'ssr', 'server': server, 'port': port,
            'cipher': method, 'password': password,
            'protocol': protocol, 'obfs': obfs,
            'protocol-param': protoparam, 'obfs-param': obfparam
        }
        return node
    except Exception as e:
        # print(f"Error parsing SSR node '{uri}': {e}") # 简化日志
        return None


# --- 核心解析函数 ---

def parse_node(node_str):
    """
    解析单个节点字符串，并返回一个字典。
    支持多种协议。
    """
    node_str = node_str.strip()
    if not node_str:
        return None

    # 尝试优先解析 VLESS
    if node_str.startswith("vless://"):
        return parse_vless_node(node_str)
    # 尝试优先解析 VMess
    elif node_str.startswith("vmess://"):
        return parse_vmess_node(node_str)
    # 对于 ss://，如果 Base64 解码后看起来像 JSON（VMess特征），则尝试用 VMess 解析
    elif node_str.startswith("ss://"):
        try:
            potential_b64_part = node_str[5:]
            decoded_ss_payload = decode_base64_url(potential_b64_part)
            if decoded_ss_payload.startswith('{') and decoded_ss_payload.endswith('}'):
                # print(f"Warning: SS URI '{node_str}' looks like VMess JSON. Attempting VMess parsing.") # 简化日志
                return parse_vmess_node(f"vmess://{potential_b64_part}")
        except Exception:
            pass # 如果解码失败或不是JSON，就按常规SS处理
        return parse_ss_node(node_str) # 尝试用SS解析器解析

    elif node_str.startswith("trojan://"):
        return parse_trojan_node(node_str)
    elif node_str.startswith("hysteria://"):
        return parse_hysteria_node(node_str)
    elif node_str.startswith("hysteria2://"):
        return parse_hysteria2_node(node_str)
    elif node_str.startswith("tuic://"):
        return parse_tuic_node(node_str)
    elif node_str.startswith("ssr://"):
        return parse_ssr_node(node_str)

    # print(f"Unsupported node protocol or malformed URI: {node_str}") # 简化日志
    return None

def get_nodes_from_subscription(url):
    """从单个订阅链接获取并解析节点"""
    nodes = []
    # print(f"Fetching subscription from: {url}") # 简化日志
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        # 尝试解码 Base64 内容
        try:
            decoded_content = decode_base64_url(response.text)
            # 在 Base64 解码后，仍然可能是 Clash YAML
            try:
                config = yaml.safe_load(decoded_content)
                if isinstance(config, dict) and 'proxies' in config:
                    # print(f"Detected Base64-encoded Clash YAML format for {url}") # 简化日志
                    for proxy_config in config['proxies']:
                        if 'name' not in proxy_config:
                             proxy_config['name'] = f"{proxy_config.get('type', 'unknown')}-{proxy_config.get('server')}:{proxy_config.get('port')}"
                        nodes.append(proxy_config)
                else:
                    # 如果不是 YAML，那就按行解析 URI
                    # print(f"Fallback to line-by-line URI parsing for Base64 content from {url}") # 简化日志
                    for line in decoded_content.splitlines():
                        node = parse_node(line.strip())
                        if node: nodes.append(node)
            except yaml.YAMLError:
                # Base64 解码后不是 YAML，按行解析 URI
                # print(f"Fallback to line-by-line URI parsing (Base64-YAML error) for {url}") # 简化日志
                for line in decoded_content.splitlines():
                    node = parse_node(line.strip())
                    if node: nodes.append(node)
        except Exception:
            # 如果不是 Base64 编码，尝试作为 Clash/Surge YAML 或纯文本处理
            try:
                # 尝试解析为 YAML (Clash)
                config = yaml.safe_load(response.text)
                if isinstance(config, dict) and 'proxies' in config:
                    # print(f"Detected Clash YAML format for {url}") # 简化日志
                    for proxy_config in config['proxies']:
                        if 'name' not in proxy_config:
                             proxy_config['name'] = f"{proxy_config.get('type', 'unknown')}-{proxy_config.get('server')}:{proxy_config.get('port')}"
                        nodes.append(proxy_config)
                else:
                    # 如果不是YAML，或者YAML中没有proxies，尝试按行解析为URI
                    # print(f"Fallback to line-by-line URI parsing for {url}") # 简化日志
                    for line in response.text.splitlines():
                        node = parse_node(line.strip())
                        if node: nodes.append(node)
            except yaml.YAMLError:
                # 再次回退到按行解析为URI
                # print(f"Fallback to line-by-line URI parsing (YAML error) for {url}") # 简化日志
                for line in response.text.splitlines():
                    node = parse_node(line.strip())
                    if node: nodes.append(node)

    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}") # 错误信息仍需输出
    except Exception as e:
        print(f"Error processing {url}: {e}") # 错误信息仍需输出
    return nodes


def merge_and_deduplicate_nodes(new_nodes, existing_nodes):
    """合并并去重节点"""
    unique_keys = set()
    deduplicated_nodes = []

    def get_node_unique_key(node):
        node_type = node.get('type')
        server = node.get('server')
        port = node.get('port')

        if not (node_type and server and port): return None

        key_parts = [node_type, server, str(port)]

        if node_type == 'ss':
            key_parts.extend([node.get('cipher'), node.get('password')])
        elif node_type == 'vmess' or node_type == 'vless':
            key_parts.append(node.get('uuid'))
            if node_type == 'vless': # VLESS XTLS flow
                key_parts.append(node.get('flow'))
        elif node_type == 'trojan':
            key_parts.append(node.get('password'))
        elif node_type == 'hysteria':
            key_parts.extend([node.get('auth'), node.get('sni'), node.get('obfs')])
        elif node_type == 'hysteria2':
            key_parts.extend([node.get('password'), node.get('sni'), node.get('obfs')])
        elif node_type == 'tuic':
            key_parts.extend([node.get('uuid'), node.get('password'), node.get('sni')])
        elif node_type == 'ssr':
            key_parts.extend([node.get('password'), node.get('protocol'), node.get('obfs')])

        # 确保关键信息都存在，否则无法生成有效的唯一键
        if all(part is not None for part in key_parts):
            return "-".join(map(str, filter(None, key_parts))) # 使用map(str, ...)确保所有部分都是字符串
        return None

    # 添加现有节点
    for node in existing_nodes:
        key = get_node_unique_key(node)
        if key and key not in unique_keys:
            unique_keys.add(key)
            deduplicated_nodes.append(node)
        elif not key: # 处理无法生成唯一键的节点，保留它们
            deduplicated_nodes.append(node)
    
    # 添加新节点并去重
    for node in new_nodes:
        key = get_node_unique_key(node)
        if key and key not in unique_keys:
            unique_keys.add(key)
            deduplicated_nodes.append(node)
        elif not key: # 处理无法生成唯一键的节点，保留它们
            deduplicated_nodes.append(node)
    
    return deduplicated_nodes


# --- YAML 保存函数 ---

def save_nodes_to_yaml(nodes, output_file="nodes.yaml"):
    """将节点保存到 YAML 文件，并尝试转换为 Clash 兼容格式"""
    script_dir = os.path.dirname(__file__)
    abs_output_file_path = os.path.join(script_dir, '..', output_file)

    clash_proxies = []
    for node in nodes:
        proxy = node.copy()
        node_type = proxy.get('type')

        if node_type == 'ss':
            proxy['udp'] = proxy.pop('udp', True)
        elif node_type == 'vmess':
            proxy['uuid'] = proxy.pop('uuid', None)
            proxy['alterId'] = proxy.pop('alterId', 0)
            proxy['cipher'] = proxy.pop('cipher', 'auto')
            proxy['tls'] = proxy.pop('tls', False)
            proxy['skip-cert-verify'] = proxy.pop('skip-cert-verify', False)
            proxy['network'] = proxy.pop('network', 'tcp')
            proxy['ws-path'] = proxy.pop('ws-path', '')
            ws_headers_host = proxy.pop('ws-headers', '')
            if ws_headers_host: proxy['ws-headers'] = {'Host': ws_headers_host}
            else: proxy.pop('ws-headers', None)
        elif node_type == 'vless':
            proxy['uuid'] = proxy.pop('uuid', None)
            proxy['network'] = proxy.pop('network', 'tcp')
            proxy['tls'] = proxy.pop('tls', False)
            proxy['udp'] = True
            if proxy.get('network') == 'ws':
                proxy['ws-path'] = proxy.pop('ws-path', '')
                ws_headers_host = proxy.pop('ws-headers', '')
                if ws_headers_host: proxy['ws-headers'] = {'Host': ws_headers_host}
                else: proxy.pop('ws-headers', None)
            elif proxy.get('network') == 'grpc':
                proxy['grpc-service-name'] = proxy.pop('grpc-service-name', '')
            proxy['flow'] = proxy.pop('flow', '')
            proxy['sni'] = proxy.pop('sni', proxy.get('server'))
            proxy['skip-cert-verify'] = proxy.pop('skip-cert-verify', False)
            proxy.pop('encryption', None)
            proxy.pop('alpn', None)
        elif node_type == 'trojan':
            proxy['password'] = proxy.pop('password', '')
            proxy['tls'] = True
            proxy['sni'] = proxy.pop('sni', proxy.get('server'))
            proxy.pop('alpn', None)
            proxy.pop('skip-cert-verify', None)
        elif node_type == 'hysteria':
            proxy['authtype'] = 'password'
            proxy['auth'] = proxy.pop('auth', '')
            proxy['up'] = proxy.pop('up', 0)
            proxy['down'] = proxy.pop('down', 0)
            proxy['alpn'] = proxy.pop('alpn', [])
            proxy['tls'] = proxy.pop('tls', True)
            proxy['sni'] = proxy.pop('sni', proxy.get('server'))
            proxy['skip-cert-verify'] = proxy.pop('skip-cert-verify', False)
            proxy['mptcp'] = proxy.pop('mptcp', False)
            proxy.pop('obfs', None)
            proxy.pop('obfs-password', None)
        elif node_type == 'hysteria2':
            proxy['password'] = proxy.pop('password', '')
            proxy['alpn'] = proxy.pop('alpn', [])
            proxy['tls'] = proxy.pop('tls', True)
            proxy['sni'] = proxy.pop('sni', proxy.get('server'))
            proxy['skip-cert-verify'] = proxy.pop('skip-cert-verify', False)
            proxy['obfs'] = proxy.pop('obfs', 'none')
            proxy['obfs-password'] = proxy.pop('obfs-password', '')
            proxy.pop('fast-open', None)
        elif node_type == 'tuic':
            proxy['uuid'] = proxy.pop('uuid', None)
            proxy['password'] = proxy.pop('password', '')
            proxy['alpn'] = proxy.pop('alpn', [])
            proxy['congestion-controller'] = proxy.pop('congestion-controller', 'bbr')
            proxy['udp-relay-mode'] = proxy.pop('udp-relay-mode', 'quic')
            proxy['tcp-fast-open'] = proxy.pop('tcp-fast-open', False)
            proxy['tls'] = proxy.pop('tls', True)
            proxy['sni'] = proxy.pop('sni', proxy.get('server'))
            proxy['skip-cert-verify'] = proxy.pop('skip-cert-verify', False)
        elif node_type == 'ssr':
            proxy['cipher'] = proxy.pop('cipher', '')
            proxy['password'] = proxy.pop('password', '')
            proxy['protocol'] = proxy.pop('protocol', '')
            proxy['protocol-param'] = proxy.pop('protocol-param', '')
            proxy['obfs'] = proxy.pop('obfs', '')
            proxy['obfs-param'] = proxy.pop('obfs-param', '')
        # 移除 'latency' 字段，因为它不再被计算
        proxy.pop('latency', None) 

        clash_proxies.append(proxy)

    with open(abs_output_file_path, 'w', encoding='utf-8') as f:
        yaml.dump({'proxies': clash_proxies}, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

# 新增函数：更新 subscriptions.txt 文件
def update_subscriptions_file(valid_subs, invalid_subs, sub_file="subscriptions.txt"):
    """
    更新 subscriptions.txt 文件，将失效的订阅链接标记为注释。
    """
    script_dir = os.path.dirname(__file__)
    abs_sub_file_path = os.path.join(script_dir, '..', sub_file)

    with open(abs_sub_file_path, 'w', encoding='utf-8') as f:
        f.write("# 有效订阅\n")
        for sub in valid_subs:
            f.write(f"{sub}\n")
        
        if invalid_subs:
            f.write("\n# 失效订阅 (连续5次未获取到节点或手动标记)\n")
            for sub in invalid_subs:
                # 确保失效链接前面有 #
                if not sub.startswith('#'):
                    f.write(f"#{sub}\n")
                else:
                    f.write(f"{sub}\n")

def main():
    # 存储每个订阅链接的失败计数
    # 使用一个字典来存储每个URL的连续失败次数
    failure_counts_file = "subscription_failure_counts.json"
    script_dir = os.path.dirname(__file__)
    abs_failure_counts_path = os.path.join(script_dir, '..', failure_counts_file)

    failure_counts = {}
    if os.path.exists(abs_failure_counts_path):
        try:
            with open(abs_failure_counts_path, 'r') as f:
                failure_counts = json.load(f)
        except json.JSONDecodeError:
            print("Error loading failure counts, starting fresh.")
            failure_counts = {}

    # 获取有效订阅和已标记的失效订阅
    subscriptions, initial_invalid_subs = fetch_subscriptions()
    
    if not subscriptions and not initial_invalid_subs:
        print("未找到任何订阅链接。程序退出。")
        return

    all_new_nodes = []
    processed_subscriptions = [] # 存储本次运行后仍有效的订阅
    newly_invalidated_subs = [] # 存储本次运行中被标记为失效的订阅

    print("--- 开始获取订阅节点 ---")
    for sub_url in subscriptions:
        current_nodes = get_nodes_from_subscription(sub_url)
        node_count = len(current_nodes)

        if node_count > 0:
            print(f"订阅链接: {sub_url} -> 获取到 {node_count} 个节点。")
            all_new_nodes.extend(current_nodes)
            failure_counts[sub_url] = 0 # 成功获取，重置失败计数
            processed_subscriptions.append(sub_url)
        else:
            print(f"订阅链接: {sub_url} -> 未获取到任何节点信息。")
            failure_counts[sub_url] = failure_counts.get(sub_url, 0) + 1
            if failure_counts[sub_url] >= 5:
                print(f"**警告**: 订阅链接 '{sub_url}' 已连续 {failure_counts[sub_url]} 次未获取到节点，将其标记为失效。")
                newly_invalidated_subs.append(sub_url)
            else:
                processed_subscriptions.append(sub_url) # 即使失败，但未达到失效次数，仍视为有效

    print(f"--- 订阅获取完成。所有订阅共获取到 {len(all_new_nodes)} 个新节点。---")

    # 更新 failure_counts.json 文件
    with open(abs_failure_counts_path, 'w') as f:
        json.dump(failure_counts, f)

    # 准备用于更新 subscriptions.txt 的列表
    final_valid_subscriptions = [sub for sub in processed_subscriptions if sub not in newly_invalidated_subs]
    final_invalid_subscriptions = initial_invalid_subs + [f"#{s}" for s in newly_invalidated_subs] # 将新失效的加上#

    # 更新 subscriptions.txt
    update_subscriptions_file(final_valid_subscriptions, final_invalid_subscriptions)
    print("subscriptions.txt 文件已更新。")

    existing_nodes = []
    abs_nodes_file_path = os.path.join(script_dir, '..', 'nodes.yaml')

    if os.path.exists(abs_nodes_file_path):
        try:
            with open(abs_nodes_file_path, 'r', encoding='utf-8') as f:
                existing_data = yaml.safe_load(f)
                if existing_data and 'proxies' in existing_data:
                    existing_nodes = existing_data['proxies']
                    print(f"已加载 {len(existing_nodes)} 个现有节点。")
        except yaml.YAMLError as e:
            print(f"加载现有 nodes.yaml 时出错: {e}。将从空节点列表开始。")
        except FileNotFoundError:
            print("nodes.yaml 未找到，将创建新文件。")

    deduplicated_nodes = merge_and_deduplicate_nodes(all_new_nodes, existing_nodes)
    print(f"合并并去重后，最终得到 {len(deduplicated_nodes)} 个唯一节点。")

    save_nodes_to_yaml(deduplicated_nodes)
    print(f"成功将 {len(deduplicated_nodes)} 个去重节点保存到 nodes.yaml (未进行连通性测试)。")

if __name__ == "__main__":
    main()
