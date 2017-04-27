#!/bin/sh

##############################################
# release.sh                                 #
# Automate rolling new trust store releases. #
##############################################

# Environment variables used by this script (note that sensible defaults
# will be used where applicable).
# - EXPIRATION_WINDOW: the minimum time certificates must be valid for
#   in order to be included in the new release. The default is 720h, or
#   30 days. This must be parsable by Go's time package.
# - NOPUSH: do not push the release branch upstream.
# - TRUST_CONFIG_PATH: the path to a cfssl-trust configuration file. The
#   default is to not specify a configuration file; the cfssl-trust program
#   will check for one in the standard places.
# - TRUST_DATABASE_PATH: the path to the cfssl-trust cert database. This
#   must either be specified here or in a configuration file.

# Fail on errors and undefined expansions; print what is being executed
# at every step.
set -eux

##########################
# PROLOGUE: release prep #
##########################

# If the path to a config file or certificate database are present as
# environment variables, then use those as flags to the cfssl-trust
# program.

CONFIG_PATH="${TRUST_CONFIG_PATH:-}"
if [ -n "${CONFIG_PATH}" ]
then
	CONFIG_PATH="-f ${CONFIG_PATH}"
fi

DATABASE_PATH="${TRUST_DATABASE_PATH:-}"
if [ -n "${DATABASE_PATH}" ]
then
	DATABASE_PATH="-d ${DATABASE_PATH}"
fi

# The expiration window defaults to 30 days.
EXPIRATION_WINDOW="${EXPIRATION_WINDOW:-720h}"

# We need to verify that we have the right tooling in place:
# cfssl-trust to perform the release, and certdump to produce
# a human-readable output of the trust stores.
check_for_tool () {
	command -v $1 2>&1 > /dev/null
	if [ $? -ne 0 ]
	then
		echo "Required tool $1 wasn't found." > /dev/stderr
		echo "Path is ${PATH}." > /dev/stderr
		exit 1
	fi
}

prologue () {
	check_for_tool cfssl-trust
	check_for_tool certdump 
	check_for_tool mktemp
	
	# This release script expects to be run from the repo's top level.
	cd "$(git rev-parse --show-toplevel)" || exit 1
}

###########
# RELEASE #
###########

release () {
	echo "Rolling trust store release at $(date +'%FT%T%z')."

	## Step 1: roll the intermediate store.
	#
	# NB: the variables shouldn't be quoted in the command line invocations.
	# The shell will interpret these as empty arguments. The most common
	# symptom of this would be seeing the error "time: invalid duration" ---
	# Go's time.ParseDuration function can't handle empty strings.
	echo "$ cfssl-trust ${DATABASE_PATH} ${CONFIG_PATH} -b int release ${EXPIRATION_WINDOW}"
	cfssl-trust ${DATABASE_PATH} ${CONFIG_PATH} -b int release ${EXPIRATION_WINDOW}
	
	# After the intermediate store is rolled, we'll need to collect the
	# new version number. cfssl-trust reports these in reverse
	# chronological order, so we can grab the first one and remove the
	# leading dash. This will serve as our release branch in git.
	LATEST_RELEASE="$(cfssl-trust ${DATABASE_PATH} ${CONFIG_PATH} releases | awk ' NR==1 { print $2 }')"
	
	## Step 2: roll the root store.
	#
	# The same caveats from step 1 apply
	echo "$ cfssl-trust ${DATABASE_PATH} ${CONFIG_PATH} -b ca release ${EXPIRATION_WINDOW}"
	cfssl-trust ${DATABASE_PATH} ${CONFIG_PATH} -b ca release ${EXPIRATION_WINDOW}

	# Add the database changes to the release git branch.
	git add cert.db
	
	## Step 3: write the trust stores to disk.
	#
	# They also should be added to the release git branch.
	echo "$ cfssl-trust ${DATABASE_PATH} ${CONFIG_PATH} -r ${LATEST_RELEASE} -b int bundle int-bundle.crt"
	cfssl-trust ${DATABASE_PATH} ${CONFIG_PATH} -r "${LATEST_RELEASE}" -b int bundle int-bundle.crt
	echo "$ cfssl-trust ${DATABASE_PATH} ${CONFIG_PATH} -r ${LATEST_RELEASE} -b ca  bundle ca-bundle.crt"
	cfssl-trust ${DATABASE_PATH} ${CONFIG_PATH} -r "${LATEST_RELEASE}" -b ca  bundle ca-bundle.crt
	git add int-bundle.crt ca-bundle.crt
	
	## Step 4: update the human-readable trust store lists.
	#
	# These lists should also be added to git.
	echo "$ certdump ca-bundle.crt  > certdata/ca-bundle.txt"
	certdump ca-bundle.crt  > certdata/ca-bundle.txt
	echo "$ certdump int-bundle.crt > certdata/int-bundle.txt"
	certdump int-bundle.crt > certdata/int-bundle.txt
	git add certdata/ca-bundle.txt certdata/int-bundle.txt

	echo "$ git status --porcelain -uno"
	git status --porcelain -uno
}

####################################
# execute: does the actual release #
####################################
execute () {
	TEMPFILE="$(mktemp)" || exit
	release | tee "$TEMPFILE"
	
	LATEST_RELEASE="$(cfssl-trust ${DATABASE_PATH} ${CONFIG_PATH} releases | awk ' NR==1 { print $2 }')"
	git checkout -b release/${LATEST_RELEASE}
	printf "Trust store release ${LATEST_RELEASE}\n\n$(cat ${TEMPFILE})" | git commit -F-
	rm ${TEMPFILE}
	
	git tag trust-store-${LATEST_RELEASE}
	
	if [ -n "${NOPUSH:-}" ]
	then
		exit 0
	fi
	
	git push --set-upstream origin release/${LATEST_RELEASE}
	git push origin trust-store-${LATEST_RELEASE}
}

prologue
execute
