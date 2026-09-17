ALTER TABLE cp_resetpass
MODIFY COLUMN code VARCHAR(64) NOT NULL,
ADD COLUMN purpose VARCHAR(16) NOT NULL DEFAULT 'password' AFTER account_id,
ADD KEY purpose_request (purpose, request_date),
ADD KEY code_purpose (code, purpose);
