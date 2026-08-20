import secrets
import json

# Алфавит без двусмысленных символов: нет 0, O, I, 1, l
CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

def generate_invite_token():
    """Генерирует читаемый invite-токен формата XXXX-XXXX-XXXX (~60 бит энтропии)"""
    def group():
        return "".join(secrets.choice(CHARSET) for _ in range(4))
    return f"{group()}-{group()}-{group()}"

def save_token(token, filename="valid_invites.json"):
    """Сохраняет токен в файл"""
    try:
        with open(filename, 'r') as f:
            tokens = json.load(f)
    except FileNotFoundError:
        tokens = []
    
    tokens.append({
        "token": token,
        "used": False,
        "created_at": __import__('time').time()
    })
    
    with open(filename, 'w') as f:
        json.dump(tokens, f, indent=2)
    
    return token

if __name__ == "__main__":
    token = generate_invite_token()
    save_token(token)
    print(f"Новый invite-токен создан:")
    print(f"beacon-invite://{token}")
    print(f"\nТокен сохранён в valid_invites.json")