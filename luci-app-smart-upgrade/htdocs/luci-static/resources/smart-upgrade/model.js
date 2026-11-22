'use strict';

function present(value) {
	return value !== null && value !== undefined && value !== '' && value !== 'unknown';
}

function display(value) {
	return present(value) ? String(value) : 'Unknown';
}

function origin(value) {
	return [ 'official', 'third_party', 'unknown' ].indexOf(value) >= 0 ? value : 'unknown';
}

function dependencies(pkg) {
	var values = Array.isArray(pkg.depends) ? pkg.depends.map(function(dep) {
		return display(dep.raw || dep.name);
	}) : [];
	return values.length ? values.join(', ') : 'Unknown';
}

function decisionRows(plan) {
	var decisions = plan && Array.isArray(plan.decisions) ? plan.decisions : [];
	return decisions.map(function(item) {
		return {
			package: display(item.package),
			decision: display(item.decision),
			target_package: display(item.target_package),
			replacements: Array.isArray(item.replacements) && item.replacements.length ?
				item.replacements.join(', ') : 'Unknown',
			reason: display(item.reason),
			compatible: item.compatible === true ? 'Yes' :
				(item.compatible === false ? 'No' : 'Unknown')
		};
	});
}

function packageRows(snapshot, plan) {
	var packages = snapshot && snapshot.packages;
	var installed = packages && Array.isArray(packages.installed) ? packages.installed : [];
	var decisions = {};
	decisionRows(plan).forEach(function(item) { decisions[item.package] = item; });
	return installed.map(function(pkg) {
		var migration = decisions[display(pkg.name)] || {};
		return {
			name: display(pkg.name),
			version: display(pkg.version),
			origin: origin(pkg.origin),
			install_reason: display(pkg.install_reason),
			confidence: display(pkg.confidence),
			evidence: Array.isArray(pkg.evidence) && pkg.evidence.length ? pkg.evidence.join(', ') : 'Unknown',
			dependencies: dependencies(pkg),
			decision: display(migration.decision),
			target_package: display(migration.target_package),
			replacements: display(migration.replacements)
		};
	});
}

function overview(snapshot, report) {
	var system = snapshot && snapshot.system || {};
	var trustedTarget = report && report.available === true && report.integrity_status === 'matched';
	return {
		distribution: display(system.distribution),
		current_version: display(system.version),
		target_version: trustedTarget ? display(report.target_version) : 'Unknown',
		current_target: display(system.target),
		current_profile: display(system.profile),
		current_architecture: display(system.package_architecture || system.architecture),
		current_package_manager: display(system.package_manager).toUpperCase(),
		target_target: trustedTarget ? display(report.target) : 'Unknown',
		target_profile: trustedTarget ? display(report.profile) : 'Unknown',
		target_architecture: trustedTarget ? display(report.architecture) : 'Unknown',
		target_package_manager: trustedTarget ? display(report.package_manager).toUpperCase() : 'Unknown',
		boot_mode: display(system.boot_mode),
		snapshot_id: display(snapshot && snapshot.snapshot_id),
		snapshot_status: display(snapshot && snapshot.status),
		identity_status: display(system.identity_status)
	};
}

function serviceRows(snapshot) {
	var services = snapshot && snapshot.services || {};
	return [ 'openclash', 'lucky', 'adguardhome', 'docker' ].map(function(name) {
		var service = services[name] || {};
		return {
			name: name,
			package_detected: service.package_detected === true ? 'Yes' :
				(service.package_detected === false ? 'No' : 'Unknown'),
			executable_exists: service.executable_exists === true ? 'Yes' :
				(service.executable_exists === false ? 'No' : 'Unknown'),
			service_definition_exists: service.service_definition_exists === true ? 'Yes' :
				(service.service_definition_exists === false ? 'No' : 'Unknown'),
			running: display(service.running)
		};
	});
}

function storage(snapshot) {
	var value = snapshot && snapshot.storage || {};
	var mounts = value.mount_inventory && Array.isArray(value.mount_inventory.entries) ?
		value.mount_inventory.entries : [];
	return {
		status: display(value.status),
		completeness: value.scan_completeness || {},
		docker: value.docker || {},
		mounts: mounts.slice(),
		targets: Array.isArray(value.targets) ? value.targets.slice() : [],
		errors: Array.isArray(value.errors) ? value.errors.slice() : []
	};
}

function formatBytes(value) {
	if (typeof value !== 'number' || !isFinite(value) || value < 0)
		return 'Unknown';
	var units = [ 'B', 'KiB', 'MiB', 'GiB', 'TiB' ];
	var index = 0;
	while (value >= 1024 && index < units.length - 1) {
		value /= 1024;
		index++;
	}
	return (index ? value.toFixed(1) : String(value)) + ' ' + units[index];
}

return {
	display: display,
	overview: overview,
	packages: packageRows,
	decisions: decisionRows,
	services: serviceRows,
	storage: storage,
	formatBytes: formatBytes
};
