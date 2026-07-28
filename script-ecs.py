import argparse
import datetime as dt
import json
import os
import sys
import time

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    sys.exit("Missing dependency: run python3 -m pip install requests")

# Silence the self-signed-cert warning when --insecure is used.
try:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore
except Exception:
    pass


class ECSClient:
    """Wrapper ajustado para a API de Gerenciamento do Dell ECS."""

    def __init__(self, host, user, password, port=443, verify=True, timeout=60):
        self.base = f"https://{host}:{port}"
        self.user = user
        self.password = password
        self.verify = verify
        self.timeout = timeout
        self.session = requests.Session()
        self.token = None

    def login(self):
        # ECS exige X-EMC-REST-CLIENT nas chamadas da API
        self.session.headers.update({
            "Accept": "application/json",
            "X-EMC-REST-CLIENT": "true"
        })

        r = self.session.get(
            f"{self.base}/login",
            auth=HTTPBasicAuth(self.user, self.password),
            verify=self.verify,
            timeout=self.timeout,
        )
        r.raise_for_status()
        self.token = r.headers.get("X-SDS-AUTH-TOKEN")
        
        if not self.token:
            raise RuntimeError("Login efetuado, mas o header X-SDS-AUTH-TOKEN não foi retornado.")

        # Atualiza a sessão com o Token do ECS
        self.session.headers.update({"X-SDS-AUTH-TOKEN": self.token})

    def logout(self):
        if self.token:
            try:
                self.session.get(f"{self.base}/logout", verify=self.verify, timeout=self.timeout)
            except Exception:
                pass


    def get(self, path, params=None, headers=None):
        """GET em um recurso da API; aceita headers adicionais se necessário."""
        url = f"{self.base}{path}"
        req_headers = self.session.headers.copy()
        if headers:
            req_headers.update(headers)

        r = self.session.get(
            url, 
            params=params, 
            headers=req_headers, 
            verify=self.verify, 
            timeout=self.timeout
        )
        r.raise_for_status()

        if not r.content:
            return {}

        try:
            return r.json()
        except ValueError:
            return {"_raw": r.text}


def _extract_list(payload, *keys):
    """Extrai listas envelopadas pelas respostas do ECS."""
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []

    for k in keys:
        val = payload.get(k)
        if isinstance(val, list):
            return val
        if isinstance(val, dict):
            return [val]
    return []


def dump(obj, out_dir, name):
    """Salva os dados como JSON formatado."""
    safe = name.replace("/", "_").replace("\\", "_").replace(":", "_")
    path = os.path.join(out_dir, f"{safe}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True, default=str)
    return path


def backup(client, root, errors):
    """Executa a rotina de extração testando fallbacks e incluindo Bucket Policies."""
    
    # ---- Configurações Globais --------------------------------------------
    glob = os.path.join(root, "global")
    os.makedirs(glob, exist_ok=True)

    global_endpoints = {
        "vdcs":                ["/object/vdcs/vdc/list", "/vdc/vdcs"],
        "storage_pools":       ["/vdc/storage-pools", "/vdc/data-service/varrays", "/vdc/data-service/vpools/storage-pools"],
        "replication_groups":  ["/vdc/data-service/vpools"],
        "nodes":               ["/vdc/nodes"],
        "management_users":    ["/vdc/users"],
        "auth_providers":      ["/vdc/admin/authnproviders"],
        "license":             ["/license"],
        "version":             ["/vdc/cluster/version", "/upgrade/version", "/object/capacity", "/object/control/ECS/version"],
        "object_cert_keystore": ["/object-cert/keystore"],  
        "syslog":               ["/vdc/syslog/config"]
    }

    for name, paths in global_endpoints.items():
        success = False
        for path in paths:
            try:
                dump(client.get(path), glob, name)
                success = True
                break
            except Exception:
                continue
        if not success:
            errors.append(f"[global] {name}: falha em todas as rotas testadas {paths}")

    # ---- Namespaces e Recursos Associados --------------------------------
    try:
        ns_payload = client.get("/object/namespaces")
    except Exception as e:
        errors.append(f"[namespaces] list: {e}")
        return

    namespaces = _extract_list(ns_payload, "namespace", "namespaces")
    dump(ns_payload, root, "namespaces_index")

    for ns in namespaces:
        ns_id = ns.get("name") or ns.get("id") or (ns if isinstance(ns, str) else None)
        if not ns_id:
            continue

        ns_dir = os.path.join(root, "namespaces", str(ns_id))
        os.makedirs(ns_dir, exist_ok=True)

        # Detalhes do Namespace
        try:
            dump(client.get(f"/object/namespaces/namespace/{ns_id}"), ns_dir, "namespace")
        except Exception as e:
            errors.append(f"[ns:{ns_id}] detail: {e}")

        # Usuários de Objeto do Namespace
        try:
            users_payload = client.get(f"/object/users/{ns_id}")
            dump(users_payload, ns_dir, "object_users")
        except Exception:
            try:
                users_payload = client.get("/object/users", params={"namespace": ns_id})
                dump(users_payload, ns_dir, "object_users")
            except Exception as e:
                errors.append(f"[ns:{ns_id}] object_users: {e}")

        # Buckets do Namespace
        try:
            buckets_payload = client.get(f"/object/bucket/namespace/{ns_id}")
            dump(buckets_payload, ns_dir, "buckets_index")
            buckets = _extract_list(buckets_payload, "object_bucket", "bucket")
        except Exception:
            try:
                buckets_payload = client.get("/object/bucket", params={"namespace": ns_id})
                dump(buckets_payload, ns_dir, "buckets_index")
                buckets = _extract_list(buckets_payload, "object_bucket", "bucket")
            except Exception as e:
                errors.append(f"[ns:{ns_id}] buckets list: {e}")
                buckets = []

        if buckets:
            b_dir = os.path.join(ns_dir, "buckets")
            os.makedirs(b_dir, exist_ok=True)

            for b in buckets:
                bname = b.get("name") or b.get("id") if isinstance(b, dict) else str(b)
                if not bname:
                    continue

                # 1. Info do Bucket
                info_success = False
                for path, params, headers in [
                    (f"/object/bucket/{bname}", {"namespace": ns_id}, None),
                    (f"/object/bucket/{bname}/info", {"namespace": ns_id}, None),
                    (f"/object/bucket/{bname}/info", None, {"x-emc-namespace": ns_id}),
                    (f"/object/bucket/{bname}", None, None), # tenta sem restrição de namespace
                ]:
                    try:
                        data = client.get(path, params=params, headers=headers)
                        dump(data, b_dir, f"{bname}__info")
                        info_success = True
                        break
                    except Exception:
                        continue
                if not info_success:
                    errors.append(f"[ns:{ns_id}] bucket {bname} info: falha ao obter detalhes")

                # 2. ACL do Bucket
                acl_success = False
                for path, params, headers in [
                    (f"/object/bucket/{bname}/acl", {"namespace": ns_id}, None),
                    (f"/object/bucket/{bname}/acl", None, {"x-emc-namespace": ns_id}),
                ]:
                    try:
                        data = client.get(path, params=params, headers=headers)
                        dump(data, b_dir, f"{bname}__acl")
                        acl_success = True
                        break
                    except Exception:
                        continue
                if not acl_success:
                    errors.append(f"[ns:{ns_id}] bucket {bname} acl: falha ao obter ACL")

                # 3. Bucket Policy (GET /object/bucket/{bucketName}/policy)
                policy_success = False
                for params, headers in [
                    ({"namespace": ns_id}, None),
                    (None, {"x-emc-namespace": ns_id}),
                ]:
                    try:
                        data = client.get(f"/object/bucket/{bname}/policy", params=params, headers=headers)
                        dump(data, b_dir, f"{bname}__policy")
                        policy_success = True
                        break
                    except Exception:
                        continue
                
                # Caso o bucket não possua política configurada, a API do ECS respondera com erro.
                # Gravamos apenas se existir para não considerar como uma falha do backup.
                if not policy_success:
                    dump({"policy": "none_or_not_configured"}, b_dir, f"{bname}__policy_none")


def prune(out_root, keep):
    """Remove backups antigos deixando apenas os N mais recentes."""
    if keep <= 0 or not os.path.exists(out_root):
        return

    entries = [
        os.path.join(out_root, d)
        for d in os.listdir(out_root)
        if d.startswith("backup_") and os.path.isdir(os.path.join(out_root, d))
    ]
    entries.sort()

    for old in entries[:-keep]:
        try:
            import shutil
            shutil.rmtree(old)
            print(f"Backup antigo removido: {old}")
        except Exception as e:
            print(f"Aviso: não foi possível remover {old}: {e}", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(
        description="Backup das configurações do Dell ECS via Management REST API."
    )
    p.add_argument("--host", default=os.environ.get("ECS_HOST"), help="Host/IP do ECS")
    p.add_argument("--user", default=os.environ.get("ECS_USER"), help="Usuário de administração")
    p.add_argument("--password", default=os.environ.get("ECS_PASSWORD"), help="Senha")
    p.add_argument("--port", type=int, default=4443, help="Porta API Mgmt (padrão 4443)")
    p.add_argument("--out", default="./ecs-backups", help="Diretório de saída")
    p.add_argument("--keep", type=int, default=30, help="Quantidade de backups a reter")
    p.add_argument("--cacert", help="Caminho do certificado CA")
    p.add_argument("--insecure", action="store_true", help="Ignora validação SSL/TLS")
    args = p.parse_args()

    missing = [n for n, v in (("host", args.host), ("user", args.user), ("password", args.password)) if not v]
    if missing:
        p.error("Campos obrigatórios ausentes: " + ", ".join(missing))

    verify = False if args.insecure else (args.cacert or True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    root = os.path.join(args.out, f"backup_{stamp}")
    os.makedirs(root, exist_ok=True)

    print(f"Iniciando backup em -> {root}")
    started = time.time()
    errors = []

    client = ECSClient(args.host, args.user, args.password, port=args.port, verify=verify)
    try:
        client.login()
        print(f"Autenticado com sucesso em {args.host}:{args.port}")
        backup(client, root, errors)
    except Exception as e:
        errors.append(f"[fatal] {e}")
    finally:
        client.logout()

    manifest = {
        "host": args.host,
        "timestamp": stamp,
        "duration_seconds": round(time.time() - started, 1),
        "errors": errors,
        "status": "ok" if not errors else "completed_with_errors",
    }
    dump(manifest, root, "_manifest")

    prune(args.out, args.keep)

    if errors:
        print(f"\nFinalizado com {len(errors)} erro(s):", file=sys.stderr)
        for e in errors:
            print("  - " + e, file=sys.stderr)
        sys.exit(1)

    print(f"Backup concluído com sucesso em {manifest['duration_seconds']}s.")


if __name__ == "__main__":
    main()
