-- ============================================================
--  Toca da Capivara: banco de dados (MySQL / MariaDB)
--  Importar:  mysql -u root -p < banco_de_dados.sql
--  (ou colar no phpMyAdmin / MySQL Workbench e executar)
-- ============================================================
CREATE DATABASE IF NOT EXISTS toca_da_capivara CHARACTER
SET
  utf8mb4 COLLATE utf8mb4_unicode_ci;

USE toca_da_capivara;

-- ------------------------------------------------------------
--  Contas (login). O nome é único sem distinguir maiúsculas
--  (Ana e ana contam como o mesmo). A palavra-passe NUNCA é
--  guardada: só o hash (scrypt) em pw_hash.
-- ------------------------------------------------------------
CREATE TABLE
  IF NOT EXISTS users (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username VARCHAR(30) NOT NULL,
    pw_hash VARCHAR(200) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username)
  ) ENGINE = InnoDB;

-- ------------------------------------------------------------
--  Sessões iniciadas (cookie). Guarda só o hash do token.
-- ------------------------------------------------------------
CREATE TABLE
  IF NOT EXISTS sessions (
    token_hash CHAR(64) NOT NULL,
    user_id INT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (token_hash),
    KEY idx_sessions_user (user_id),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
  ) ENGINE = InnoDB;


-- ------------------------------------------------------------
--  Consultas úteis (tira o "--" para usar)
-- ------------------------------------------------------------
-- Perfil de uma conta, do mais recente para o mais antigo:
--   SELECT * FROM perfil_dos_videos_baixados WHERE conta = 'Ana' ORDER BY baixado_em DESC;
-- Quantos vídeos cada conta tem:
--   SELECT u.username, COUNT(h.id) AS videos FROM users u LEFT JOIN history h ON h.user_id = u.id GROUP BY u.id;
-- Limpar o perfil de uma conta:
--   DELETE FROM history WHERE user_id = (SELECT id FROM users WHERE username = 'Ana');
-- Apagar sessões com mais de 30 dias:
--   DELETE FROM sessions WHERE created_at < NOW() - INTERVAL 30 DAY;