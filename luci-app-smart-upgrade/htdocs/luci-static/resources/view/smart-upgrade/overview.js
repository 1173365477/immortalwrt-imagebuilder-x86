'use strict';
'require view';
'require rpc';
'require ui';
'require poll';
'require smart-upgrade.model as model';

var callStatus = rpc.declare({ object: 'smart_upgrade', method: 'status', expect: {} });
var callScan = rpc.declare({ object: 'smart_upgrade', method: 'scan', expect: {} });
var callSnapshot = rpc.declare({ object: 'smart_upgrade', method: 'snapshot', expect: {} });
var callPlan = rpc.declare({ object: 'smart_upgrade', method: 'plan', expect: {} });
var callReport = rpc.declare({ object: 'smart_upgrade', method: 'report', expect: {} });

function rpcFallback(error) {
	return {
		available: false,
		error_code: 'RPC_UNAVAILABLE',
		error_message: error && error.message ? error.message : _('Permission denied or RPC unavailable'),
		dispatch_allowed: false,
		flash_ready: false
	};
}

function badge(value) {
	var text = model.display(value);
	var safe = [ 'ok', 'completed', 'matched', 'consistent', 'official', 'running' ].indexOf(String(value)) >= 0;
	var danger = [ 'failed', 'blocked', 'mismatch', 'conflict', 'third_party' ].indexOf(String(value)) >= 0;
	return E('span', { 'class': 'smart-upgrade-badge ' + (safe ? 'is-ok' : danger ? 'is-danger' : 'is-unknown') }, text);
}

function section(title, description, content) {
	return E('section', { 'class': 'cbi-section smart-upgrade-section' }, [
		E('h2', {}, title),
		description ? E('p', { 'class': 'smart-upgrade-description' }, description) : '',
		content
	]);
}

function keyValueTable(rows) {
	return E('div', { 'class': 'table smart-upgrade-kv' }, rows.map(function(row) {
		return E('div', { 'class': 'tr' }, [
			E('div', { 'class': 'td left', 'data-title': _('Field') }, row[0]),
			E('div', { 'class': 'td left', 'data-title': _('Value') }, row[1])
		]);
	}));
}

function messageList(values, className) {
	if (!Array.isArray(values) || !values.length)
		return E('p', { 'class': 'smart-upgrade-muted' }, _('None reported'));
	return E('ul', { 'class': className || '' }, values.map(function(value) {
		return E('li', {}, String(value));
	}));
}

return view.extend({
	load: function() {
		return Promise.all([
			callStatus().catch(rpcFallback),
			callSnapshot().catch(rpcFallback),
			callPlan().catch(rpcFallback),
			callReport().catch(rpcFallback)
		]);
	},

	handleScan: function(ev) {
		var button = ev.currentTarget;
		button.disabled = true;
		button.classList.add('spinning');
		return callScan().then(function(result) {
			if (result.error_code)
				throw new Error(result.error_message || result.error_code);
			window.location.reload();
		}).catch(function(error) {
			ui.addNotification(null, E('p', {}, [ _('Read-only scan failed: '), error.message ]));
			button.disabled = false;
			button.classList.remove('spinning');
		});
	},

	handleExport: function(report) {
		var suffix = String(report.snapshot_id || 'unknown').replace(/^urn:sha256:/, '').slice(0, 16);
		var blob = new Blob([ report.content || '' ], { type: 'text/markdown;charset=utf-8' });
		var url = URL.createObjectURL(blob);
		var anchor = document.createElement('a');
		anchor.href = url;
		anchor.download = 'migration-report-' + suffix + '.md';
		document.body.appendChild(anchor);
		anchor.click();
		anchor.remove();
		URL.revokeObjectURL(url);
	},

	renderOverview: function(snapshot, report) {
		var value = model.overview(snapshot, report);
		return section(_('System and target overview'),
			_('Target fields are shown only when a Migration Plan is bound to the current Snapshot.'),
			keyValueTable([
				[ _('Distribution'), value.distribution ],
				[ _('Current version'), value.current_version ],
				[ _('Target version'), value.target_version ],
				[ _('Current target / profile'), value.current_target + ' / ' + value.current_profile ],
				[ _('Current architecture'), value.current_architecture ],
				[ _('Current package manager'), value.current_package_manager ],
				[ _('Target target / profile'), value.target_target + ' / ' + value.target_profile ],
				[ _('Target architecture'), value.target_architecture ],
				[ _('Target package manager'), value.target_package_manager ],
				[ _('Boot mode'), badge(snapshot && snapshot.system && snapshot.system.boot_mode) ],
				[ _('Identity'), badge(snapshot && snapshot.system && snapshot.system.identity_status) ],
				[ _('Snapshot ID'), value.snapshot_id ],
				[ _('Snapshot completeness'), badge(snapshot && snapshot.status) ]
			]));
	},

	renderScanner: function(status, snapshotEnvelope) {
		var error = status.error_message || snapshotEnvelope.error_message;
		var content = E('div', {}, [
			keyValueTable([
				[ _('State'), badge(status.scan_status) ],
				[ _('Started'), model.display(status.started_at) ],
				[ _('Completed'), model.display(status.completed_at) ],
				[ _('Snapshot status'), badge(status.snapshot_status) ],
				[ _('Error'), model.display(error) ]
			]),
			E('div', { 'class': 'cbi-page-actions' }, [
				E('button', {
					'class': 'btn cbi-button cbi-button-action',
					'disabled': status.scan_status === 'running',
					'click': ui.createHandlerFn(this, 'handleScan')
				}, status.scan_status === 'running' ? _('Scanning…') : _('Start read-only scan'))
			])
		]);
		return section(_('Read-only scanner'),
			_('The scanner reads fixed system evidence. It does not change packages, services, configuration, containers, or disks.'), content);
	},

	renderPackages: function(snapshot, plan) {
		var rows = model.packages(snapshot, plan);
		var decisions = model.decisions(plan);
		var planAvailable = !!plan;
		var packages = snapshot && snapshot.packages || {};
		var warning = !Array.isArray(packages.top_level) || packages.top_level.length === 0 ?
			E('div', { 'class': 'alert-message warning' },
				_('Top-level package evidence is empty. Every installed package remains visible and unclassified intent stays Unknown.')) : '';
		var table = E('div', { 'class': 'table smart-upgrade-wide-table' }, [
			E('div', { 'class': 'tr table-titles' }, [
				E('div', { 'class': 'th' }, _('Package')),
				E('div', { 'class': 'th' }, _('Version')),
				E('div', { 'class': 'th' }, _('Origin')),
				E('div', { 'class': 'th' }, _('Install reason')),
				E('div', { 'class': 'th' }, _('Confidence')),
				E('div', { 'class': 'th' }, _('Migration decision')),
				E('div', { 'class': 'th' }, _('Evidence / dependencies'))
			])
		].concat(rows.map(function(pkg) {
			return E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td', 'data-title': _('Package') }, pkg.name),
				E('div', { 'class': 'td', 'data-title': _('Version') }, pkg.version),
				E('div', { 'class': 'td', 'data-title': _('Origin') }, badge(pkg.origin)),
				E('div', { 'class': 'td', 'data-title': _('Install reason') }, pkg.install_reason),
				E('div', { 'class': 'td', 'data-title': _('Confidence') }, pkg.confidence),
				E('div', { 'class': 'td', 'data-title': _('Migration decision') }, [
					badge(pkg.decision),
					E('small', {}, _('Target: ') + pkg.target_package + '; ' + _('Replacements: ') + pkg.replacements)
				]),
				E('div', { 'class': 'td', 'data-title': _('Evidence / dependencies') }, [
					E('div', {}, pkg.evidence), E('small', {}, pkg.dependencies)
				])
			]);
		})));
		var unresolved = decisions.filter(function(item) {
			return item.decision === 'block' || item.decision === 'review';
		});
		var replacements = decisions.filter(function(item) { return item.decision === 'replace'; });
		return section(_('Package evidence'),
			_('Origin and installation intent are copied from scanner evidence; Unknown is never promoted to Official.'),
			E('div', {}, [
				warning,
				planAvailable ? '' : E('div', { 'class': 'alert-message warning' },
					_('Migration Plan is unavailable. Package migration decisions and replacements are Unknown.')),
				rows.length ? table : E('p', {}, _('No installed package evidence is available.')),
				E('h3', {}, _('Missing or unresolved packages')),
				!planAvailable ? E('p', { 'class': 'smart-upgrade-muted' }, _('Unknown — Migration Plan unavailable')) : unresolved.length ? messageList(unresolved.map(function(item) {
					return item.package + ': ' + item.reason;
				}), 'smart-upgrade-blockers') : E('p', { 'class': 'smart-upgrade-muted' }, _('None reported by the Migration Plan')),
				E('h3', {}, _('Replacement packages')),
				!planAvailable ? E('p', { 'class': 'smart-upgrade-muted' }, _('Unknown — Migration Plan unavailable')) : replacements.length ? messageList(replacements.map(function(item) {
					return item.package + ' → ' + item.target_package + ' (' + item.replacements + ')';
				})) : E('p', { 'class': 'smart-upgrade-muted' }, _('None reported by the Migration Plan'))
			]));
	},

	renderServicesAndStorage: function(snapshot) {
		var services = model.services(snapshot);
		var storage = model.storage(snapshot);
		var serviceTable = E('div', { 'class': 'table' }, [
			E('div', { 'class': 'tr table-titles' }, [
				E('div', { 'class': 'th' }, _('Service')),
				E('div', { 'class': 'th' }, _('Package')),
				E('div', { 'class': 'th' }, _('Executable')),
				E('div', { 'class': 'th' }, _('Service definition')),
				E('div', { 'class': 'th' }, _('Runtime'))
			])
		].concat(services.map(function(service) {
			return E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td' }, service.name),
				E('div', { 'class': 'td' }, service.package_detected),
				E('div', { 'class': 'td' }, service.executable_exists),
				E('div', { 'class': 'td' }, service.service_definition_exists),
				E('div', { 'class': 'td' }, badge(service.running))
			]);
		})));
		var mountTable = E('div', { 'class': 'table smart-upgrade-wide-table' }, storage.mounts.map(function(mount) {
			return E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td', 'data-title': _('Mount') }, model.display(mount.mountpoint)),
				E('div', { 'class': 'td', 'data-title': _('Device') }, model.display(mount.device)),
				E('div', { 'class': 'td', 'data-title': _('Filesystem') }, model.display(mount.filesystem)),
				E('div', { 'class': 'td', 'data-title': _('Device size') }, model.formatBytes(mount.size_bytes)),
				E('div', { 'class': 'td', 'data-title': _('Available space') }, model.formatBytes(mount.available_bytes)),
				E('div', { 'class': 'td', 'data-title': _('Risk') }, badge(mount.risk))
			]);
		}));
		var targetTable = E('div', { 'class': 'table smart-upgrade-wide-table' }, storage.targets.map(function(target) {
			return E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td', 'data-title': _('Kind') }, model.display(target.kind)),
				E('div', { 'class': 'td', 'data-title': _('Source') }, model.display(target.source)),
				E('div', { 'class': 'td', 'data-title': _('Persistence') }, model.display(target.persistence)),
				E('div', { 'class': 'td', 'data-title': _('Disk overwrite risk') }, badge(target.firmware_overwrite_risk)),
				E('div', { 'class': 'td', 'data-title': _('Verified') }, target.verified === true ? _('Yes') : _('No / Unknown'))
			]);
		}));
		return section(_('Services and storage risk'),
			_('Missing evidence is Partial or Unknown and is never presented as safe.'),
			E('div', {}, [
				keyValueTable([
					[ _('Storage status'), badge(storage.status) ],
					[ _('Docker daemon evidence'), model.display(storage.docker.daemon_state) ],
					[ _('Docker root'), model.display(storage.docker.root) ],
					[ _('Container coverage'), model.display(storage.completeness.containers) ],
					[ _('Volume coverage'), model.display(storage.completeness.volumes) ],
					[ _('Mount coverage'), model.display(storage.completeness.mounts) ]
				]),
				E('h3', {}, _('Services')), serviceTable,
				E('h3', {}, _('Mounts')), storage.mounts.length ? mountTable : E('p', {}, _('Mount evidence is Unknown.')),
				E('h3', {}, _('Docker and storage targets')), storage.targets.length ? targetTable : E('p', {}, _('No verified Docker or storage target evidence is available.')),
				storage.errors.length ? E('div', { 'class': 'alert-message warning' }, messageList(storage.errors)) : ''
			]));
	},

	renderReport: function(report) {
		if (!report.available)
			return section(_('Migration report'),
				_('Reports are generated by the trusted analysis pipeline, not by this page.'),
				E('div', { 'class': 'alert-message warning' }, report.error_message || _('Migration Report is unavailable.')));
		var integrityWarning = report.integrity_status === 'matched' ? '' :
			E('div', { 'class': 'alert-message warning' },
				_('Report Snapshot identity is not matched to the current scan. Target fields remain untrusted.'));
		return section(_('Migration report'),
			_('Compatibility, blockers, and build status are displayed exactly as supplied by the Migration Plan.'),
			E('div', {}, [
				integrityWarning,
				keyValueTable([
					[ _('Snapshot ID'), model.display(report.snapshot_id) ],
					[ _('Plan ID'), model.display(report.plan_id) ],
					[ _('Plan status'), badge(report.plan_status) ],
					[ _('Target version'), model.display(report.target_version) ],
					[ _('Compatibility'), badge(report.compatibility) ],
					[ _('Build allowed'), report.build_allowed === true ? _('Yes') : _('No') ],
					[ _('Flash ready'), _('No (MVP invariant)') ]
				]),
				E('h3', { 'class': 'smart-upgrade-blocker-title' }, _('Blockers')),
				messageList(report.blockers, 'smart-upgrade-blockers'),
				E('h3', {}, _('Warnings')), messageList(report.warnings),
				E('h3', {}, _('Report content')),
				E('pre', { 'class': 'smart-upgrade-report' }, report.content || _('Empty report')),
				E('div', { 'class': 'cbi-page-actions' }, [
					E('button', {
						'class': 'btn cbi-button cbi-button-neutral',
						'click': ui.createHandlerFn(this, function() { this.handleExport(report); })
					}, _('Export report'))
				])
			]));
	},

	render: function(data) {
		if (!document.querySelector('link[data-smart-upgrade-style]'))
			document.head.appendChild(E('link', {
				'rel': 'stylesheet', 'href': L.resource('smart-upgrade.css'),
				'data-smart-upgrade-style': '1'
			}));
		var status = data[0] || rpcFallback();
		var snapshotEnvelope = data[1] || rpcFallback();
		var planEnvelope = data[2] || rpcFallback();
		var report = data[3] || rpcFallback();
		var evidence = model.bindEvidence(snapshotEnvelope, planEnvelope, report);
		var snapshot = evidence.snapshot;
		var plan = evidence.plan;
		if (evidence.report.available !== true)
			evidence.report.error_message = report.available === true ?
				_('Migration evidence does not match this scan. Refresh to try again.') : report.error_message;
		var root = E('div', { 'class': 'smart-upgrade-page' }, [
			E('h1', {}, _('Smart Upgrade')),
			E('div', { 'class': 'alert-message warning' },
				_('Read-only Sprint 3 view. Dispatch and flashing are disabled; build allowed never means flash ready.')),
			this.renderOverview(snapshot, evidence.report),
			this.renderScanner(status, snapshotEnvelope),
			this.renderPackages(snapshot, plan),
			this.renderServicesAndStorage(snapshot),
			this.renderReport(evidence.report)
		]);
		var stateNode = root.querySelector('.smart-upgrade-section:nth-of-type(2) .smart-upgrade-badge');
		poll.add(function() {
			return callStatus().then(function(next) {
				if (stateNode)
					stateNode.textContent = model.display(next.scan_status);
			});
		}, 5);
		return root;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
