'use strict';
'require baseclass';

function identity(envelope) {
	if (!envelope || envelope.available !== true || envelope.integrity_status !== 'verified' ||
	    !/^urn:sha256:[a-f0-9]{64}$/.test(envelope.snapshot_id) ||
	    !/^[a-f0-9]{64}-[1-9][0-9]{0,11}-[1-9][0-9]{0,9}$/.test(envelope.scan_generation) ||
	    !/^[a-f0-9]{64}$/.test(envelope.snapshot_sha256))
		return null;
	return {
		snapshot_id: envelope.snapshot_id,
		scan_generation: envelope.scan_generation,
		snapshot_sha256: envelope.snapshot_sha256
	};
}

function sameScan(a, b) {
	return a && b && a.snapshot_id === b.snapshot_id &&
		a.scan_generation === b.scan_generation && a.snapshot_sha256 === b.snapshot_sha256;
}

function fresh(expiresAt, now) {
	return Number.isSafeInteger(expiresAt) && expiresAt > now;
}

function AnalysisDisplay() {
	this.sequence = 0;
	this.target = null;
	this.scan = null;
	this.pending = false;
	this.result = null;
}

AnalysisDisplay.prototype.invalidate = function() {
	this.sequence++;
	this.pending = false;
	this.result = null;
};

AnalysisDisplay.prototype.select = function(target) {
	this.target = target;
	this.invalidate();
};

AnalysisDisplay.prototype.begin = function() {
	this.invalidate();
	this.pending = true;
	this.scan = null;
	return this.sequence;
};

AnalysisDisplay.prototype.capture = function(sequence, envelope, now) {
	var scan = identity(envelope);
	if (sequence !== this.sequence || !this.pending || !scan || !this.target || !fresh(this.target.expires_at, now))
		return null;
	this.scan = scan;
	return {
		sequence: sequence, scan: scan, target_ref: this.target.target_ref,
		resolution_digest: this.target.resolution_digest
	};
};

AnalysisDisplay.prototype.accept = function(ticket, response, envelope, now) {
	if (!this.pending || ticket.sequence !== this.sequence)
		return false;
	this.pending = false;
	if (!this.target || this.target.target_ref !== ticket.target_ref ||
	    this.target.resolution_digest !== ticket.resolution_digest || !fresh(this.target.expires_at, now) ||
	    !sameScan(ticket.scan, identity(envelope)) || !response || response.available !== true ||
	    response.dispatch_allowed !== false || response.flash_ready !== false ||
	    !sameScan(ticket.scan, response) || ticket.resolution_digest !== response.resolution_digest ||
	    !fresh(response.expires_at, now) || [ 'eligible', 'blocked' ].indexOf(response.status) < 0)
		return false;
	this.result = response;
	return true;
};

AnalysisDisplay.prototype.expire = function(now) {
	if (this.target && !fresh(this.target.expires_at, now)) {
		this.select(null);
		return true;
	}
	if (this.result && !fresh(this.result.expires_at, now)) {
		this.invalidate();
		return true;
	}
	return false;
};

AnalysisDisplay.prototype.observe = function(envelope, now) {
	if (this.expire(now))
		return true;
	if ((this.pending || this.result) && this.scan && !sameScan(this.scan, identity(envelope))) {
		this.invalidate();
		return true;
	}
	return false;
};

return baseclass.extend({
	AnalysisDisplay: AnalysisDisplay,
	fresh: fresh
});
