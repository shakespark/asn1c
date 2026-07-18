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
	# Figure out the initial source file used to generate this output.
	src=$(echo "$ref" | sed -e 's/\.-[-a-zA-Z0-9=]*$//')
	# Figure out compiler flags used to create the file.
	flags=$(echo "$ref" | sed -e 's/.*\.-//')
	echo "Checking $src against $ref"
	template=.tmp.check-parsing.$$
	oldversion=${template}.old
	newversion=${template}.new
	# Diagnostics embed the .asn1 file path, whose relative depth depends
	# on the build layout (in-tree, VPATH, distcheck's _build/sub); strip
	# the path prefix on both sides so the comparison is layout-agnostic.
	LANG=C sed -e 's/^found in .*/found in .../' \
		-e 's![^ ]*/tests-asn1c-compiler/!!g' \
		-e 's![^ ]*/standard-modules/!!g' < "$ref" > "$oldversion"
	ec=0
	(${top_builddir}/asn1c/asn1c -S ${top_srcdir}/skeletons -no-gen-OER -no-gen-PER "-$flags" "$src" 2>&1 | LANG=C sed -e 's/^found in .*/found in .../' \
		-e 's![^ ]*/tests-asn1c-compiler/!!g' \
		-e 's![^ ]*/standard-modules/!!g' > "$newversion") || ec=$?
	if [ $? = 0 ]; then
		diff $diffArgs "$oldversion" "$newversion" || ec=$?
	fi
	if [ $ec != 0 ]; then
		LAST_FAILED="$ref (from $src)"
		finalExitCode=$ec
	fi
	rm -f $oldversion $newversion
	if [ "$1" = "regenerate" ]; then
		${top_builddir}/asn1c/asn1c -S ${top_srcdir}/skeletons -no-gen-OER -no-gen-PER "-$flags" "$src" > "$ref" 2>&1
	fi
done

exit $finalExitCode
