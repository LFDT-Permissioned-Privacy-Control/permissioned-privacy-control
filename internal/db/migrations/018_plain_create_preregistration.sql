-- Allow plain CREATE pre-registrations: factory and salt are only meaningful for CREATE3
ALTER TABLE preregistered_addresses
    ALTER COLUMN factory DROP NOT NULL,
    ALTER COLUMN salt DROP NOT NULL;

---- create above / drop below ----

ALTER TABLE preregistered_addresses
    ALTER COLUMN factory SET NOT NULL,
    ALTER COLUMN salt SET NOT NULL;
