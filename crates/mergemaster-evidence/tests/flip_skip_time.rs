//! Timestamp contracts through the native CLIs and the independent pinned Python source.
#[path = "../src/pinned_python.rs"]
mod pinned_python;

// Reuse the frozen operational API/shim inputs, not either implementation's parser.
// All generated scripts live in temporary directories; no Python source is added.
const DIFFERENTIAL: &str = r#"
import copy, datetime, json, os, pathlib, shutil, subprocess, sys, tempfile

repository, binary, command, suite = sys.argv[1:]
repository = pathlib.Path(repository)
fixture = json.loads((repository / 'tests/fixtures/oracle' / (command + '.json')).read_text())
source = pathlib.Path(os.environ['MERGEMASTER_PYTHON_ORACLE']) / 'scripts' / ('evidence-' + command)
base = fixture['cases'][0]
now = fixture['now']

# A single run makes acceptance independently visible in the jobs endpoint calls.
def api_at(stamp):
    api = copy.deepcopy(base['api'])
    api['runs'] = api['runs'][:1]
    api['runs'][0]['created_at'] = stamp
    if command == 'skip-report':
        api['release_runs'][0]['created_at'] = stamp
    return api


def compare(label, api, accepted=True, expected_minutes=None, expected_window_start=None):
    with tempfile.TemporaryDirectory(prefix='mergemaster-time-') as temporary:
        root = pathlib.Path(temporary)
        for tool in ('git', 'gh'):
            executable = root / tool
            executable.write_text('#!' + sys.executable + '\n' + fixture['shim'])
            executable.chmod(0o700)
        (root / 'api.json').write_text(json.dumps(api))
        for name, content in (base.get('files') or {}).items():
            (root / name).write_text(content)
        environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                           FLIP_SKIP_API=str(root / 'api.json'), FLIP_SKIP_CALLS=str(root / 'calls'))
        if suite == 'display':
            environment['TZ'] = 'Europe/Berlin'
        arguments = ['--repo', 'org/repo', '--cache', str(root / 'cache'),
                     *[arg.replace('${root}', str(root)) for arg in base['argv']]]
        observations = []
        for implementation in ('python', 'native'):
            shutil.rmtree(root / 'cache', ignore_errors=True)
            (root / 'calls').write_text('')
            if implementation == 'python':
                invocation = [sys.executable, '-I', '-B', '-c', fixture['launcher'],
                              str(source), now, str(root), *arguments]
            else:
                invocation = [binary, 'evidence', command, '--now', now, *arguments]
            done = subprocess.run(invocation, cwd=root, env=environment, capture_output=True)
            context = (command, suite, label, implementation)
            assert done.returncode == 0, (context, done.returncode, done.stdout, done.stderr)
            assert done.stderr == b'', (context, done.stderr)
            report = json.loads(done.stdout)
            if command == 'flip-ready' and implementation == 'python':
                # The inherited Python bug labels the original offset wall clock
                # as Z. TZ=UTC cannot fix explicit input offsets. Normalize only
                # this field and its verbatim interpolation in the reason.
                for check in report['checks'].values():
                    if check['log_window_start'] is None:
                        continue
                    instant = datetime.datetime.fromisoformat(api['runs'][0]['created_at'])
                    old = instant.strftime('%Y-%m-%dT%H:%M:%SZ')
                    utc = instant.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                    assert check['log_window_start'] == old, (context, check)
                    check['log_window_start'] = utc
                    check['why_not'] = [
                        'log window started ' + utc + ', less than 24 h ago'
                        if reason == 'log window started ' + old + ', less than 24 h ago'
                        else reason for reason in check['why_not']
                    ]
            if expected_window_start is not None:
                check = report['checks']['lint']
                assert check['log_window_start'] == expected_window_start, (context, check)
                assert check['why_not'] == [
                    'log window started ' + expected_window_start + ', less than 24 h ago'
                ], (context, check)
            calls = [json.loads(line) for line in (root / 'calls').read_text().splitlines()]
            paths = [call[-1] for call in calls if call[:2] == ['gh', 'api']]
            assert any('/runs/1/jobs?' in path for path in paths) == accepted, (context, paths)
            if command == 'skip-report':
                assert report['runs'] == int(accepted), (context, report)
                assert report['release_surface']['runs'] == int(accepted), (context, report)
                if expected_minutes is not None:
                    assert report['release_surface']['minutes'] == expected_minutes, (context, report)
                    assert report['release_surface']['macos_minutes'] == expected_minutes, (context, report)
            observations.append((report, sorted(paths)))
        assert observations[0] == observations[1], (command, suite, label, observations)


if suite == 'forms':
    for label, stamp, accepted in [
        ('reduced-hour', '2026-11-20T10Z', True),
        ('reduced-minute', '2026-11-20T10:00Z', True),
        ('basic', '20261120T100000Z', True),
        ('week', '2026-W47-5T10:00:00Z', True),
        ('basic-week', '2026W475T100000+0000', True),
        ('week-default-monday-outside-window', '2026-W47T10:00Z', False),
        ('basic-week-default-monday', '2026W47T1000+00', False),
        ('space-separator', '2026-11-20 10:00:00+00:00', True),
        ('unicode-separator', '2026-11-20\U0001f64210:00:00Z', True),
        ('offset-hour', '2026-11-20T11+01', True),
        ('offset-basic', '20261120T113000+0130', True),
        ('offset-seconds', '2026-11-20T11:30:15+01:30:15', True),
        ('offset-fraction-truncation', '2026-11-20T11:30:15.1234567+01:30:15.1234569', True),
        ('negative-offset', '2026-11-20T08:30:00-01:30', True),
        ('comma-fraction', '2026-11-20T10:00:00,123456789Z', True),
        ('long-fraction', '2026-11-20T10:00:00.123456789Z', True),
        ('naive-date', '2026-11-20', False),
        ('naive-datetime', '2026-11-20T10:00:00.123456789', False),
        ('naive-basic', '20261120T100000', False),
        ('naive-week', '2026-W47-5T10:00', False),
    ]:
        compare(label, api_at(stamp), accepted)
elif suite == 'boundaries':
    # flip-ready fetches 26 hours (the report itself uses a 24-hour log window).
    lower = '10' if command == 'flip-ready' else '12'
    for label, stamp, accepted in [
        ('lower-inclusive', '2026-11-19T' + lower + ':00:00Z', True),
        ('lower-before-microsecond', '2026-11-19T' + ('09' if lower == '10' else '11') + ':59:59.9999999Z', False),
        ('upper-inclusive', '2026-11-20T12:00:00Z', True),
        # CPython truncates, rather than rounds, the seventh and later digits.
        ('upper-submicrosecond-truncates-inside', '2026-11-20T12:00:00.000000999Z', True),
        ('upper-one-microsecond-outside', '2026-11-20T12:00:00.000001Z', False),
        ('upper-offset-fractions-cancel', '2026-11-20T13:30:15.1234569+01:30:15.1234561', True),
    ]:
        compare(label, api_at(stamp), accepted)
elif suite == 'display':
    # Under a non-UTC process TZ, output must still represent real UTC instants.
    for label, stamp, expected in [
        ('positive-offset', '2026-11-20T11+01', '2026-11-20T10:00:00Z'),
        ('negative-offset-crosses-date', '2026-11-19T23:30:00-10:30', '2026-11-20T10:00:00Z'),
        ('fractional-offset-upper-bound', '2026-11-20T13:30:15.1234569+01:30:15.1234561', '2026-11-20T12:00:00Z'),
    ]:
        compare(label, api_at(stamp), expected_window_start=expected)
elif suite == 'durations':
    for label, start, end, expected in [
        ('basic', '20261120T100000Z', '20261120T100130Z', 1.5),
        ('reduced', '2026-11-20T10Z', '2026-11-20T10:03Z', 3.0),
        ('week', '2026-W47-5T10:00:00Z', '2026W475T100130+0000', 1.5),
        ('offset-seconds', '2026-11-20T11:30:15+01:30:15', '2026-11-20T08:31:30-01:30', 1.5),
        ('naive-start-ignored', '2026-11-20T10:00:00', '2026-11-20T10:01:30Z', 0.0),
        ('naive-end-ignored', '2026-11-20T10:00:00Z', '2026-11-20T10:01:30', 0.0),
        # Both fractions truncate to zero microseconds. Retaining nanoseconds moves
        # 0.25 minutes just above the one-decimal rounding boundary (0.2 -> 0.3).
        ('submicrosecond-rounding-boundary', '2026-11-20T10:00:00.0000001Z', '2026-11-20T10:00:15.0000009Z', 0.2),
        ('three-seconds-audit-example', '2026-11-20T10:00:00.0000009Z', '2026-11-20T10:00:03Z', 0.1),
        ('decimal-rounding-below-half', '2026-11-20T10:00:00Z', '2026-11-20T10:00:09Z', 0.1),
        ('decimal-rounding-below-half-later', '2026-11-20T10:00:00Z', '2026-11-20T10:00:21Z', 0.3),
        ('negative-duration-clamped', '2026-11-20T10:01:30Z', '2026-11-20T10:00:00Z', 0.0),
    ]:
        api = api_at('2026-11-20T10:00:00Z')
        job = api['jobs']['3'][0]
        job['started_at'], job['completed_at'] = start, end
        api['jobs']['3'] = [job]
        compare(label, api, expected_minutes=expected)
else:
    raise AssertionError(suite)
"#;

fn differential(command: &str, suite: &str) {
    let root = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set at test runtime"),
    )
    .join("../..");
    let output = pinned_python::command()
        .args(["-B", "-c", DIFFERENTIAL])
        .arg(root)
        .arg(
            std::env::var_os("CARGO_BIN_EXE_mergemaster")
                .expect("CARGO_BIN_EXE_mergemaster is set at test runtime"),
        )
        .args([command, suite])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{command}/{suite}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn flip_ready_python_isoformat_forms_and_naive_rejection() {
    differential("flip-ready", "forms");
}

#[test]
fn skip_report_python_isoformat_forms_and_naive_rejection() {
    differential("skip-report", "forms");
}

#[test]
fn flip_ready_window_boundaries_truncate_to_microseconds() {
    differential("flip-ready", "boundaries");
}

#[test]
fn skip_report_window_boundaries_truncate_to_microseconds() {
    differential("skip-report", "boundaries");
}

#[test]
fn flip_ready_displays_real_utc_under_non_utc_process_timezone() {
    differential("flip-ready", "display");
}

#[test]
fn skip_report_release_durations_use_zoned_microsecond_times() {
    differential("skip-report", "durations");
}
