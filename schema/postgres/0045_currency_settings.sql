-- One application-owned currency configuration. Currency is metadata; the
-- configured Value member remains the rate-input fact coordinate. Settings
-- are not an executable FX policy until rate semantics are certified.
ALTER TABLE epm.application_state
    ADD COLUMN currency_settings jsonb
        CHECK (currency_settings IS NULL OR
               jsonb_typeof(currency_settings) = 'object');

GRANT UPDATE (currency_settings) ON epm.application_state TO epm_runtime;
