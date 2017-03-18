-- The trust database contains a listing of all the certificates we
-- use, the sources for those certificates, and release information
-- for the sake of deterministic builds of bundles.

-- schema_version contains release information for this database.
CREATE TABLE IF NOT EXISTS schema_version (
	revision	INTEGER UNIQUE PRIMARY KEY,
	created_at	INTEGER
);

-- Schema version 1 (initial schema): created
-- 2017-02-01T23:25:48+0000.
INSERT INTO schema_version (revision, created_at)
	-- Don't insert this version into the database if it already
	-- exists.
	SELECT 1, 1485991500
	WHERE NOT EXISTS (SELECT 1 FROM schema_version
				WHERE revision = 1);

-- certificates contains the actual certificates.
--
-- Note 1: the 'raw' field is the DER-encoded certificate.
--
-- Note 2: it isn't sufficient to use the SKI (which is a hash of the
-- certificate's public key) as a primary key or to force a UNIQUE
-- constraint on it. It's entirely possible for the same public key to
-- have a certificate regenerated. This is why the UNIQUE constraint
-- is on the ski/serial pair.
CREATE TABLE IF NOT EXISTS certificates (
	ski		TEXT NOT NULL,
	aki		TEXT NOT NULL,
	serial		BLOB NOT NULL,
	not_before	INTEGER NOT NULL,
	not_after	INTEGER NOT NULL,
	raw		BLOB NOT NULL,
	UNIQUE(ski, serial)
);

-- sources pairs an authority access information field URL to an
-- SKI. This can be used in some cases to obtain updates for expiring
-- certificates.
CREATE TABLE IF NOT EXISTS sources (
	ski	TEXT NOT NULL,
	url	TEXT NOT NULL,
	FOREIGN KEY (ski) REFERENCES certificates(ski)
);

-- The AIA table stores a reference URL for each provided AIA in
-- certificates. This can be used to fetch new intermediates, and
-- should generally match the 'source' table.
CREATE TABLE IF NOT EXISTS aia (
	ski	TEXT PRIMARY KEY,
	url	TEXT NOT NULL,
	FOREIGN KEY (ski) REFERENCES certificates(aki)
);

-- The revocations table stores a list of all revocations that have
-- occurred.
CREATE TABLE IF NOT EXISTS revocations (
	ski		TEXT PRIMARY KEY,
	revoked_at	INTEGER NOT NULL,
	mechanism	TEXT NOT NULL,
	reason		TEXT NOT NULL,
	FOREIGN KEY (ski) REFERENCES certificates(ski)
);

-- The roots table is a list of root certificates.
CREATE TABLE IF NOT EXISTS roots (
	ski		TEXT NOT NULL,
	serial		BLOB NOT NULL,
	release		TEXT NOT NULL,
	UNIQUE (ski, serial, release)
	FOREIGN KEY (ski) REFERENCES certificates(ski),
	FOREIGN KEY (release) REFERENCES root_releases(version)

);

-- The root_releases contains metadata about a given root bundle
-- release, facilitating deterministic bundle rebuilds.
CREATE TABLE IF NOT EXISTS root_releases (
	version		TEXT PRIMARY KEY,
	released_at	INTEGER UNIQUE NOT NULL
);

-- The intermediates table is a list of root intermediates.
CREATE TABLE IF NOT EXISTS intermediates (
	ski		TEXT NOT NULL,
	serial		BLOB NOT NULL,
	release		TEXT NOT NULL,
	UNIQUE (ski, serial, release)
	FOREIGN KEY (ski) REFERENCES certificates(ski),
	FOREIGN KEY (release) REFERENCES intermediate_releases(version)
);

-- The intermediate_releases contains metadata about a given
-- intermediate bundle release, facilitating deterministic bundle
-- rebuilds.
CREATE TABLE IF NOT EXISTS intermediate_releases (
	version		TEXT PRIMARY KEY,
	released_at	INTEGER UNIQUE NOT NULL
);
