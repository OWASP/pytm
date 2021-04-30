# 1.2.0

## Breaking changes

- Replace `usesLatestTLSversion` with `minTLSVersion` in assets and `tlsVersion` in data flows [#123](https://github.com/izar/pytm/pull/123)
- When the `data` attribute of elements is initialied with a string, convert it to a `Data` object with `undefined` as name and the string as description; change the default classification from `PUBLIC` to `UNKNOWN` [#148](https://github.com/izar/pytm/pull/148)

## New features

- Separate actors and assets from elements when dumping the model to JSON [#150](https://github.com/izar/pytm/pull/150)
- Add unique Finding ids [#154](https://github.com/izar/pytm/pull/154)
- Allow to associate the threat model script with source code files and check their age difference [#145](https://github.com/izar/pytm/pull/145)
- Adapt [the DFD3 notation](https://github.com/adamshostack/DFD3) [#143](https://github.com/izar/pytm/pull/143)
- Allow to override findings (threats) attributes [#137](https://github.com/izar/pytm/pull/137)
- Allow to mark data as PII or credentials and check if it's protected [#127](https://github.com/izar/pytm/pull/127)
- Added '--levels' - every element now has a 'levels' attribute, a list of integers denoting different DFD levels for rendering
- Added HTML docs using pdoc [#110](https://github.com/izar/pytm/pull/110)
- Added `checksDestinationRevocation` attribute to account for certificate revocation checks [#109](https://github.com/izar/pytm/pull/109)

## Bug fixes

- Escape HTML entities in Threat attributes [#149](https://github.com/izar/pytm/pull/149)
- Fix generating reports for models with a `Datastore` that has `isEncryptedAtRest` set and a `Data` that has `isStored` set [#141](https://github.com/izar/pytm/pull/141)
- Fix condition on the `Data Leak` threat so it does not always match [#139](https://github.com/izar/pytm/pull/139)
- Fixed printing the data attribute in reports [#123](https://github.com/izar/pytm/pull/123)
- Added a markdown file with threats [#126](https://github.com/izar/pytm/pull/126)
- Fixed drawing nested boudnaries [#117](https://github.com/izar/pytm/pull/117)
- Add missing `provideIntegrity` attribute in `Actor` and `Asset` classes [#116](https://github.com/izar/pytm/pull/116)

# 1.1.2

- Added Poetry [#108](https://github.com/izar/pytm/pull/108)
- Fix drawing DFDs for nested Boundaries [#107](https://github.com/izar/pytm/pull/107)

# 1.1.1

- Fix pydal dependencies install on pip [#106](https://github.com/izar/pytm/pull/106)

# 1.1.0

## Breaking changes

- Removed `HandlesResources` attribute from the `Process` class, which duplicates `handlesResources`
- Change default `Dataflow.dstPort` attribute value from `10000` to `-1`

## New features


- Add dump of elements and findings to sqlite database using "--sqldump <database>" (with result in ./sqldump/) [#103](https://github.com/izar/pytm/pull/103)
- Add Data element and DataLeak finding to support creation of a data dictionary separate from the model [#104](https://github.com/izar/pytm/pull/104)
- Add JSON input [#105](https://github.com/izar/pytm/pull/105)
- Add JSON output [#102](https://github.com/izar/pytm/pull/102)
- Use numbered dataflow labels in sequence diagram [#94](https://github.com/izar/pytm/pull/94)
- Move authenticateDestination to base Element [#88](https://github.com/izar/pytm/pull/88)
- Assign inputs and outputs to all elements [#89](https://github.com/izar/pytm/pull/89)
- Allow detecting and/or hiding duplicate dataflows by setting `TM.onDuplicates` [#100](https://github.com/izar/pytm/pull/100)
- Ignore unused elements if `TM.ignoreUnused` is True [#84](https://github.com/izar/pytm/pull/84)
- Assign findings to elements [#86](https://github.com/izar/pytm/pull/86)
- Add description to class attributes [#91](https://github.com/izar/pytm/pull/91)
- New Element methods to be used in threat conditions [#82](https://github.com/izar/pytm/pull/82)
- Provide a Docker image and allow running make targets in a container [#87](https://github.com/izar/pytm/pull/87)
- Dataflow inherits source and/or sink attribute values [#79](https://github.com/izar/pytm/pull/79)
- Merge edges in DFD when `TM.mergeResponses` is True; allow marking `Dataflow` as responses [#76](https://github.com/izar/pytm/pull/76)
- Automatic ordering of dataflows when `TM.isOrdered` is True [#66](https://github.com/izar/pytm/pull/66)
- Loading a custom threats file by setting `TM.threatsFile` [#68](https://github.com/izar/pytm/pull/68)
- Setting properties on init [#67](https://github.com/izar/pytm/pull/67)
- Wrap long labels in DFDs [#65](https://github.com/izar/pytm/pull/65)

## Bug fixes

- Ensure all items have correct color, based on scope [#93](https://github.com/izar/pytm/pull/93)
- Add missing server isResilient property [#63](https://github.com/izar/pytm/issues/63)
- Advanced templates in repeat blocks [#81](https://github.com/izar/pytm/pull/81)
- Produce stable diagrams [#79](https://github.com/izar/pytm/pull/79)
- Allow overriding classes [#64](https://github.com/izar/pytm/pull/64)

# 1.0.0

## New features

- New threats [#61](https://github.com/izar/pytm/pull/61)

## Bug fixes

- UnicodeDecodeError: 'charmap' codec can't decode byte 0x9d [#57](https://github.com/izar/pytm/pull/57)
- `_uniq_name` missing 1 required positional argument [#60](https://github.com/izar/pytm/pull/60)
- Render objects with duplicate names [#45](https://github.com/izar/pytm/issues/45)

# 0.8.1

## Bug fixes

- Draw nested boundaries [#54](https://github.com/izar/pytm/pull/54),  [#55](https://github.com/izar/pytm/pull/55)

# 0.8.0

## New features

- Draw nested boundaries [#52](https://github.com/izar/pytm/pull/52)
