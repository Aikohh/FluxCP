ALTER TABLE cp_emailchange
MODIFY COLUMN code VARCHAR(64) NOT NULL,
ADD KEY code_pending (code, change_done);
