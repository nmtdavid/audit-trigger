-- Un historial de auditoría es importante en la mayoría de las Tablas de la Base de Datos. 
-- Proporcionar un Trigger de auditoría que registra a una tabla de auditoría las transacciones.
--
-- Este archivo debe ser genérica y no depender de las funciones de aplicación o estructuras,
-- Como está siendo anunciado aquí: https://wiki.postgresql.org/wiki/Audit_trigger_91plus
--
-- Este disparador se basó originalmente en http://wiki.postgresql.org/wiki/Audit_trigger
-- Pero ha sido reescrito por completo.
--
-- En realidad debería ser convertido en una extensión reubicable, con control y actualizar archivos.

CREATE EXTENSION IF NOT EXISTS hstore;

CREATE SCHEMA auditoria;
REVOKE ALL ON SCHEMA auditoria FROM public;

COMMENT ON SCHEMA auditoria IS 'Datos auditado/historico registro de eventos Tablas y funciones Trigger';

--
-- Datos auditados. Gran cantidad de información está disponible, es sólo una cuestión de cuánto 
-- realmente desea grabar. Ver: http://www.postgresql.org/docs/9.1/static/functions-info.html
--
-- Recuerde, cada columna que se agrega ocupa más espacio en tabla de auditoría y ralentiza inserción 
-- de registros auditoría. 
--
-- También cada índice se agrega tiene un gran impacto, así que evite agregar índices a la tabla de
-- registro de auditoría a menos que realmente se necesite. Los índices hstore GIST son especialmente
-- costosos.
--
-- A veces es recomendable realizar una copia de la tabla de auditoría, o un subconjunto del mismo 
-- que le interesa, en una tabla temporal y crear cualquier índice útil y sobre eso hacer su análisis
--
CREATE TABLE auditoria.registro_comportamiento (
    event_id bigserial primary key,
    schema_name text not null,
    table_name text not null,
    relid oid not null,
    session_user_name text,
    action_tstamp_tx TIMESTAMP WITH TIME ZONE NOT NULL,
    action_tstamp_stm TIMESTAMP WITH TIME ZONE NOT NULL,
    action_tstamp_clk TIMESTAMP WITH TIME ZONE NOT NULL,
    transaction_id bigint,
    application_name text,
    client_addr inet,
    client_port integer,
    client_query text,
    action TEXT NOT NULL CHECK (action IN ('I','D','U', 'T')),
    row_data hstore,
    changed_fields hstore,
    statement_only boolean not null
);

REVOKE ALL ON auditoria.registro_comportamiento FROM public;

COMMENT ON TABLE auditoria.registro_comportamiento IS 'Rastro de las acciones auditables en las tablas auditadas, desde auditoria.if_modified_func()';
COMMENT ON COLUMN auditoria.registro_comportamiento.event_id IS 'Identificador único para cada evento auditable';
COMMENT ON COLUMN auditoria.registro_comportamiento.schema_name IS 'Esquema de tabla de auditoría de base de datos para este evento es en';
COMMENT ON COLUMN auditoria.registro_comportamiento.table_name IS 'Non-schema-qualified nombre del evento se produjo en la tabla';
COMMENT ON COLUMN auditoria.registro_comportamiento.relid IS 'Tabla OID. Los cambios de la drop/create. Obtener con ''tablename''::regclass';
COMMENT ON COLUMN auditoria.registro_comportamiento.session_user_name IS 'Login/session nombre usuario que provoco el evento auditado';
COMMENT ON COLUMN auditoria.registro_comportamiento.action_tstamp_tx IS 'Transacción fecha y hora de inicio de tx en el que se produjo evento auditado';
COMMENT ON COLUMN auditoria.registro_comportamiento.action_tstamp_stm IS 'Declaración de fecha y hora inicio de tx en el que se produjo evento auditado';
COMMENT ON COLUMN auditoria.registro_comportamiento.action_tstamp_clk IS 'Tiempo en la que audita evento''s llamada de trigger';
COMMENT ON COLUMN auditoria.registro_comportamiento.transaction_id IS 'Identificador de transacción que hizo el cambio. Puede envolver, pero se combina con action_tstamp_tx.';
COMMENT ON COLUMN auditoria.registro_comportamiento.client_addr IS 'Dirección IP del cliente que emitió la consulta. Null para socket UNIX.';
COMMENT ON COLUMN auditoria.registro_comportamiento.client_port IS 'distancia entre dirección IP del puerto de cliente que emitió la consulta. Indefinido deunix socket.';
COMMENT ON COLUMN auditoria.registro_comportamiento.client_query IS 'Top-level consulta que causó este evento auditable. Puede haber más de una declaración.';
COMMENT ON COLUMN auditoria.registro_comportamiento.application_name IS 'Application name set when this audit event occurred. Can be changed in-session by client.';
COMMENT ON COLUMN auditoria.registro_comportamiento.action IS 'Acción; I = insert, D = delete, U = update, T = truncate';
COMMENT ON COLUMN auditoria.registro_comportamiento.row_data IS 'Valor de registro. Null para statement-level trigger. Para INSERT esta es la nueva tupla. Para DELETE y UPDATE es la ultima tupla.';
COMMENT ON COLUMN auditoria.registro_comportamiento.changed_fields IS 'Los nuevos valores de los campos modificados por UPDATE. Null excepto por row-level UPDATE eventos.';
COMMENT ON COLUMN auditoria.registro_comportamiento.statement_only IS '''t'' si el evento es de una auditoría FOR EACH STATEMENT trigger, ''f'' para FOR EACH ROW';

CREATE INDEX logged_actions_relid_idx ON auditoria.registro_comportamiento(relid);
CREATE INDEX logged_actions_action_tstamp_tx_stm_idx ON auditoria.registro_comportamiento(action_tstamp_stm);
CREATE INDEX logged_actions_action_idx ON auditoria.registro_comportamiento(action);

CREATE OR REPLACE FUNCTION auditoria.if_modified_func() RETURNS TRIGGER AS $body$
DECLARE
    audit_row audit.registro_comportamiento;
    include_values boolean;
    log_diffs boolean;
    h_old hstore;
    h_new hstore;
    excluded_cols text[] = ARRAY[]::text[];
BEGIN
    IF TG_WHEN <> 'AFTER' THEN
        RAISE EXCEPTION 'audit.if_modified_func() may only run as an AFTER trigger';
    END IF;

    audit_row = ROW(
        nextval('audit.logged_actions_event_id_seq'), -- event_id
        TG_TABLE_SCHEMA::text,                        -- schema_name
        TG_TABLE_NAME::text,                          -- table_name
        TG_RELID,                                     -- relation OID for much quicker searches
        session_user::text,                           -- session_user_name
        current_timestamp,                            -- action_tstamp_tx
        statement_timestamp(),                        -- action_tstamp_stm
        clock_timestamp(),                            -- action_tstamp_clk
        txid_current(),                               -- transaction ID
        current_setting('application_name'),          -- client application
        inet_client_addr(),                           -- client_addr
        inet_client_port(),                           -- client_port
        current_query(),                              -- top-level query or queries (if multistatement) from client
        substring(TG_OP,1,1),                         -- action
        NULL, NULL,                                   -- row_data, changed_fields
        'f'                                           -- statement_only
        );

    IF NOT TG_ARGV[0]::boolean IS DISTINCT FROM 'f'::boolean THEN
        audit_row.client_query = NULL;
    END IF;

    IF TG_ARGV[1] IS NOT NULL THEN
        excluded_cols = TG_ARGV[1]::text[];
    END IF;
    
    IF (TG_OP = 'UPDATE' AND TG_LEVEL = 'ROW') THEN
        audit_row.row_data = hstore(OLD.*) - excluded_cols;
        audit_row.changed_fields =  (hstore(NEW.*) - audit_row.row_data) - excluded_cols;
        IF audit_row.changed_fields = hstore('') THEN
            -- All changed fields are ignored. Skip this update.
            RETURN NULL;
        END IF;
    ELSIF (TG_OP = 'DELETE' AND TG_LEVEL = 'ROW') THEN
        audit_row.row_data = hstore(OLD.*) - excluded_cols;
    ELSIF (TG_OP = 'INSERT' AND TG_LEVEL = 'ROW') THEN
        audit_row.row_data = hstore(NEW.*) - excluded_cols;
    ELSIF (TG_LEVEL = 'STATEMENT' AND TG_OP IN ('INSERT','UPDATE','DELETE','TRUNCATE')) THEN
        audit_row.statement_only = 't';
    ELSE
        RAISE EXCEPTION '[audit.if_modified_func] - Trigger func added as trigger for unhandled case: %, %',TG_OP, TG_LEVEL;
        RETURN NULL;
    END IF;
    INSERT INTO auditoria.logged_actions VALUES (audit_row.*);
    RETURN NULL;
END;
$body$
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;


COMMENT ON FUNCTION auditoria.if_modified_func() IS $body$
Track changes to a table at the statement and/or row level.

Optional parameters to trigger in CREATE TRIGGER call:

param 0: boolean, whether to log the query text. Default 't'.

param 1: text[], columns to ignore in updates. Default [].

         Updates to ignored cols are omitted from changed_fields.

         Updates with only ignored cols changed are not inserted
         into the audit log.

         Almost all the processing work is still done for updates
         that ignored. If you need to save the load, you need to use
         WHEN clause on the trigger instead.

         No warning or error is issued if ignored_cols contains columns
         that do not exist in the target table. This lets you specify
         a standard set of ignored columns.

There is no parameter to disable logging of values. Add this trigger as
a 'FOR EACH STATEMENT' rather than 'FOR EACH ROW' trigger if you do not
want to log row values.

Note that the user name logged is the login role for the session. The audit trigger
cannot obtain the active role because it is reset by the SECURITY DEFINER invocation
of the audit trigger its self.
$body$;



CREATE OR REPLACE FUNCTION auditoria.audit_table(target_table regclass, audit_rows boolean, audit_query_text boolean, ignored_cols text[]) RETURNS void AS $body$
DECLARE
  stm_targets text = 'INSERT OR UPDATE OR DELETE OR TRUNCATE';
  _q_txt text;
  _ignored_cols_snip text = '';
BEGIN
    EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_row ON ' || quote_ident(target_table::TEXT);
    EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_stm ON ' || quote_ident(target_table::TEXT);

    IF audit_rows THEN
        IF array_length(ignored_cols,1) > 0 THEN
            _ignored_cols_snip = ', ' || quote_literal(ignored_cols);
        END IF;
        _q_txt = 'CREATE TRIGGER audit_trigger_row AFTER INSERT OR UPDATE OR DELETE ON ' || 
                 quote_ident(target_table::TEXT) || 
                 ' FOR EACH ROW EXECUTE PROCEDURE auditoria.if_modified_func(' ||
                 quote_literal(audit_query_text) || _ignored_cols_snip || ');';
        RAISE NOTICE '%',_q_txt;
        EXECUTE _q_txt;
        stm_targets = 'TRUNCATE';
    ELSE
    END IF;

    _q_txt = 'CREATE TRIGGER audit_trigger_stm AFTER ' || stm_targets || ' ON ' ||
             target_table ||
             ' FOR EACH STATEMENT EXECUTE PROCEDURE auditoria.if_modified_func('||
             quote_literal(audit_query_text) || ');';
    RAISE NOTICE '%',_q_txt;
    EXECUTE _q_txt;

END;
$body$
language 'plpgsql';

COMMENT ON FUNCTION auditoria.audit_table(regclass, boolean, boolean, text[]) IS $body$
Add auditing support to a table.

Arguments:
   target_table:     Table name, schema qualified if not on search_path
   audit_rows:       Record each row change, or only auditoria at a statement level
   audit_query_text: Record the text of the client query that triggered the audit event?
   ignored_cols:     Columns to exclude from update diffs, ignore updates that change only ignored cols.
$body$;

-- Pg doesn't allow variadic calls with 0 params, so provide a wrapper
CREATE OR REPLACE FUNCTION auditoria.audit_table(target_table regclass, audit_rows boolean, audit_query_text boolean) RETURNS void AS $body$
SELECT auditoria.audit_table($1, $2, $3, ARRAY[]::text[]);
$body$ LANGUAGE SQL;

-- And provide a convenience call wrapper for the simplest case
-- of row-level logging with no excluded cols and query logging enabled.
--
CREATE OR REPLACE FUNCTION auditoria.audit_table(target_table regclass) RETURNS void AS $body$
SELECT audit.audit_table($1, BOOLEAN 't', BOOLEAN 't');
$body$ LANGUAGE 'sql';

COMMENT ON FUNCTION audit.audit_table(regclass) IS $body$
Add auditing support to the given table. Row-level changes will be logged with full client query text. No cols are ignored.
$body$;
