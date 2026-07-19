#!/bin/sh

# Test diff(1) capabilities
diff -a . . 2>/dev/null && diffArgs="-a"		# Assume text files
diff -u . . 2>/dev/null && diffArgs="$diffArgs -u"	# Unified diff output

finalExitCode=0

if [ "$1" != "regenerate" ]; then
    set -e
fi

LAST_FAILED=""
print_status() {
    if [ -n "${LAST_FAILED}" ]; then
        echo "Error while processing $LAST_FAILED"
    fi
}

trap print_status EXIT

top_srcdir="${top_srcdir:-../..}"
top_builddir="${top_builddir:-../..}"

for ref in ${top_srcdir}/tests/tests-asn1c-compiler/*.asn1.-*; do
	# Skip the exit-code sidecar files themselves: they match the golden
	# glob above (it's a substring match), but are not goldens.
	case "$ref" in
		*.exitcode) continue ;;
	esac
	# Figure out the initial source file used to generate this output.
	src=$(echo "$ref" | sed -e 's/\.-[-a-zA-Z0-9=]*$//')
	# Figure out compiler flags used to create the file.
	flags=$(echo "$ref" | sed -e 's/.*\.-//')
	echo "Checking $src against $ref"
	template=.tmp.check-parsing.$$
	oldversion=${template}.old
	newversion=${template}.new
	rawoutput=${template}.raw
	# Diagnostics embed the .asn1 file path, whose relative depth depends
	# on the build layout (in-tree, VPATH, distcheck's _build/sub); strip
	# the path prefix on both sides so the comparison is layout-agnostic.
	LANG=C sed -e 's/^found in .*/found in .../' \
		-e 's![^ ]*/tests-asn1c-compiler/!!g' \
		-e 's![^ ]*/standard-modules/!!g' < "$ref" > "$oldversion"

	# Fixtures that exercise error diagnostics (parse/semantic failures,
	# etc.) are expected to make the compiler exit with a non-zero
	# status. That expectation is recorded in a "<ref>.exitcode" sidecar
	# file; fixtures without one are expected to exit with status 0.
	exitcode_ref="${ref}.exitcode"
	if [ -f "$exitcode_ref" ]; then
		expected_ec=$(cat "$exitcode_ref")
	else
		expected_ec=0
	fi

	# Capture the compiler's own exit code directly, into a plain file
	# first: piping straight into sed would have the pipeline's exit
	# code reflect sed's status (always 0), silently discarding a
	# compiler crash or non-zero exit. Normalize the captured output
	# afterwards, as a separate step.
	ec=0
	${top_builddir}/asn1c/asn1c -S ${top_srcdir}/skeletons -no-gen-OER -no-gen-PER "-$flags" "$src" > "$rawoutput" 2>&1 || ec=$?
	LANG=C sed -e 's/^found in .*/found in .../' \
		-e 's![^ ]*/tests-asn1c-compiler/!!g' \
		-e 's![^ ]*/standard-modules/!!g' < "$rawoutput" > "$newversion"

	if [ "$ec" != "$expected_ec" ]; then
		echo "Exit code mismatch for $ref: expected $expected_ec, got $ec"
		ec=1
	elif ! diff $diffArgs "$oldversion" "$newversion"; then
		ec=1
	else
		ec=0
	fi

	if [ $ec != 0 ]; then
		LAST_FAILED="$ref (from $src)"
		finalExitCode=$ec
	fi
	rm -f $oldversion $newversion $rawoutput
	if [ "$1" = "regenerate" ]; then
		${top_builddir}/asn1c/asn1c -S ${top_srcdir}/skeletons -no-gen-OER -no-gen-PER "-$flags" "$src" > "$ref" 2>&1
		new_ec=$?
		if [ "$new_ec" != 0 ]; then
			echo "$new_ec" > "$exitcode_ref"
		else
			rm -f "$exitcode_ref"
		fi
	fi
done

exit $finalExitCode
