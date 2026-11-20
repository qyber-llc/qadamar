import { useEffect, useState, useCallback } from 'react';
import { api } from '../api/client';
import type {
  AdminResource,
  AdminSubject,
  AdminTuple,
  ConsoleRole,
  SchemaResponse,
} from '../api/types';
import { ErrorAlert, LoadingState } from '../components/UiStates';
import { useT } from '../i18n';
import { ModelSchemaPane } from './ModelSchemaPane';
import { ModelTablesPane } from './ModelTablesPane';
import { ResourceInventoryPane } from './ResourceInventoryPane';

type ModelTab = 'schema' | 'subjects' | 'resources' | 'tuples' | 'inventory';

export function AttributeModelScreen(props: {
  readonly roles: readonly ConsoleRole[];
  readonly params: Readonly<Record<string, string>>;
  readonly setParams: (updates: Readonly<Record<string, string | undefined>>) => void;
}) {
  const t = useT();
  const activeTab: ModelTab =
    props.params.tab === 'subjects' || props.params.tab === 'resources' || props.params.tab === 'tuples' || props.params.tab === 'inventory'
      ? props.params.tab
      : 'schema';

  const [schema, setSchema] = useState<SchemaResponse | null>(null);
  const [subjects, setSubjects] = useState<readonly AdminSubject[]>([]);
  const [resources, setResources] = useState<readonly AdminResource[]>([]);
  const [tuples, setTuples] = useState<readonly AdminTuple[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [sc, sub, res, tup] = await Promise.all([
        api.getSchema(),
        api.getSubjects(),
        api.getResources(),
        api.getTuples(),
      ]);
      setSchema(sc);
      setSubjects(sub.items);
      setResources(res.items);
      setTuples(tup.items);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  return (
    <section aria-labelledby="title-model">
      <div className="screen-header">
        <div>
          <h1 className="screen-title" id="title-model">
            {t.model.title}
          </h1>
          <p className="screen-subtitle">
            {t.model.subtitle}
          </p>
        </div>
      </div>

      <div className="tab-bar" role="group" aria-label={t.model.sections}>
        {(['schema', 'subjects', 'resources', 'tuples', 'inventory'] as const).map((tab) => (
          <button
            key={tab}
            type="button"
            className="tab-btn"
            aria-pressed={activeTab === tab}
            onClick={() => props.setParams({ tab, q: undefined, level: undefined, comp: undefined, status: undefined, rtype: undefined })}
          >
            {tab === 'schema' && t.model.tabSchema}
            {tab === 'subjects' && t.model.tabSubjects(subjects.length)}
            {tab === 'resources' && t.model.tabResources(resources.length)}
            {tab === 'tuples' && t.model.tabTuples(tuples.length)}
            {tab === 'inventory' && t.model.tabInventory}
          </button>
        ))}
      </div>

      {loading ? <LoadingState label={t.model.loading} /> : null}
      {error ? <ErrorAlert error={error} contextTitle={t.model.loadFailed} onRetry={() => void loadAll()} /> : null}

      {!loading && !error && schema && activeTab === 'schema' ? (
        <ModelSchemaPane schema={schema} />
      ) : null}

      {!loading && !error && activeTab === 'inventory' ? (
        <ResourceInventoryPane schema={schema} roles={props.roles} params={props.params} setParams={props.setParams} />
      ) : null}

      {!loading && !error && activeTab !== 'schema' && activeTab !== 'inventory' ? (
        <ModelTablesPane
          activeTab={activeTab}
          roles={props.roles}
          schema={schema}
          subjects={subjects}
          resources={resources}
          tuples={tuples}
          params={props.params}
          setParams={props.setParams}
        />
      ) : null}
    </section>
  );
}
