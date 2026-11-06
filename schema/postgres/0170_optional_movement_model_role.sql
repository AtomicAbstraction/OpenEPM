-- A Movement axis is optional financial-application metadata. Generic FP&A
-- applications remain valid without it; this only permits an explicit role.
-- The inline 0005 constraint has this stable PostgreSQL-derived identity.
-- Naming it exactly makes unexpected predecessor drift fail closed instead of
-- selecting and dropping an arbitrary check that happens to mention the column.
ALTER TABLE epm.dimension DROP CONSTRAINT dimension_model_role_check;
ALTER TABLE epm.dimension ADD CONSTRAINT dimension_model_role_check CHECK(
  model_role IS NULL OR model_role IN(
    'Scenario','Year','Period','View','Entity','Value','Account','ICP',
    'Currency','DataType','Custom','Movement'));
