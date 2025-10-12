"""
Универсальная инициализация keyring для всех платформ при сборке Nuitka
"""
import sys
import keyring
from keyring.backend import KeyringBackend


def init_keyring():
    """Инициализирует правильный keyring бэкенд для текущей платформы"""
    
    # Проверяем, собрано ли приложение
    is_frozen = getattr(sys, 'frozen', False) or '__compiled__' in globals()
    
    if not is_frozen:
        # Обычный запуск через Python - keyring сам разберется
        return
    
    # Для собранного приложения явно устанавливаем бэкенд
    platform = sys.platform
    backend = None
    
    try:
        if platform == 'win32':
            # Windows - используем Windows Credential Manager
            from keyring.backends.Windows import WinVaultKeyring
            backend = WinVaultKeyring()
            print("Using Windows Credential Manager")
            
        elif platform == 'darwin':
            # macOS - используем Keychain
            from keyring.backends.macOS import Keyring as MacKeyring
            backend = MacKeyring()
            print("Using macOS Keychain")
            
        elif platform.startswith('linux'):
            # Linux - пробуем SecretService (GNOME Keyring/KWallet)
            try:
                from keyring.backends.SecretService import Keyring as SecretServiceKeyring
                backend = SecretServiceKeyring()
                print("Using Linux SecretService")
            except Exception as e:
                print(f"SecretService not available: {e}")
                # Fallback на зашифрованный файл
                raise
        
        if backend:
            # Проверяем, что бэкенд работает
            try:
                backend.priority  # Это заставит бэкенд инициализироваться
                keyring.set_keyring(backend)
                print(f"Keyring backend set successfully: {type(backend).__name__}")
                return
            except Exception as e:
                print(f"Backend failed initialization: {e}")
                
    except Exception as e:
        print(f"Could not load platform keyring: {e}")
    
    # Fallback - используем зашифрованный файл
    print("Falling back to encrypted file storage")
    try:
        from keyrings.alt.file import EncryptedKeyring
        backend = EncryptedKeyring()
        keyring.set_keyring(backend)
        print("Using EncryptedKeyring fallback")
    except Exception as e:
        print(f"Could not set EncryptedKeyring: {e}")
        # Последний вариант - PlaintextKeyring (с предупреждением)
        try:
            from keyrings.alt.file import PlaintextKeyring
            backend = PlaintextKeyring()
            keyring.set_keyring(backend)
            print("WARNING: Using PlaintextKeyring - credentials are NOT encrypted!")
        except Exception as final_e:
            print(f"CRITICAL: No keyring backend available: {final_e}")
            raise RuntimeError("Cannot initialize any keyring backend")


# Автоматически инициализируем при импорте
init_keyring()