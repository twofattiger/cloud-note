-- 备忘录数据表
CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL DEFAULT '',      -- 列表标题（从正文首行派生）
  content TEXT NOT NULL DEFAULT '',    -- 富文本 HTML
  format INTEGER NOT NULL DEFAULT 0,   -- 0=明文，1=以后启用加密时的密文
  updated_at INTEGER NOT NULL          -- 毫秒时间戳
);

-- 登录防爆破：按 IP 记录失败次数与封禁截止时间
CREATE TABLE IF NOT EXISTS login_attempts (
  ip TEXT PRIMARY KEY,
  fails INTEGER NOT NULL DEFAULT 0,
  first_fail_at INTEGER NOT NULL DEFAULT 0,
  banned_until INTEGER NOT NULL DEFAULT 0
);
-- 标签
CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  color TEXT NOT NULL DEFAULT '#8a8a8f'
);

-- 笔记-标签多对多关联
CREATE TABLE IF NOT EXISTS note_tags (
  note_id INTEGER NOT NULL,
  tag_id INTEGER NOT NULL,
  PRIMARY KEY (note_id, tag_id),
  FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
  FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

-- 回收站：软删除支持
ALTER TABLE notes ADD COLUMN deleted_at INTEGER DEFAULT NULL;
