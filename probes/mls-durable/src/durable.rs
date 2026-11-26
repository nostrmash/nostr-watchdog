//! SQLite-backed Durable Object. Each request loads the OpenMLS snapshot,
//! performs one operation, and writes the new snapshot before responding.
//! The response does not contain the snapshot.

use worker::*;

use crate::step;

#[durable_object]
pub struct MlsGroupObject {
    sql: SqlStorage,
}

impl DurableObject for MlsGroupObject {
    fn new(state: State, _env: Env) -> Self {
        let sql = state.storage().sql();
        sql.exec(
            "CREATE TABLE IF NOT EXISTS mls_state (id TEXT PRIMARY KEY, snapshot TEXT NOT NULL)",
            None,
        )
        .expect("create mls_state");
        Self { sql }
    }

    async fn fetch(&self, _req: Request) -> Result<Response> {
        let previous = self
            .sql
            .exec("SELECT snapshot FROM mls_state WHERE id = 'group'", None)?
            .to_array::<Row>()?
            .into_iter()
            .next()
            .map(|row| row.snapshot);
        let outcome = step(previous.as_deref().map(|text| text.as_bytes()))
            .map_err(|error| Error::from(error.to_string()))?;
        let snapshot = String::from_utf8(outcome.snapshot).map_err(|_| Error::from("mls_snapshot"))?;
        self.sql.exec("DELETE FROM mls_state WHERE id = 'group'", None)?;
        self.sql.exec(
            "INSERT INTO mls_state (id, snapshot) VALUES ('group', ?)",
            vec![snapshot.into()],
        )?;
        Response::from_json(&serde_json::json!({
            "created": outcome.created,
            "epoch": outcome.epoch,
            "messageBytes": outcome.message_bytes,
            "storageEntries": outcome.storage_entries
        }))
    }
}

#[derive(serde::Deserialize)]
struct Row {
    snapshot: String,
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let namespace = env.durable_object("MLS_GROUP")?;
    let id = namespace.id_from_name("probe")?;
    let stub = id.get_stub()?;
    stub.fetch_with_request(req).await
}
