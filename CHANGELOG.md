# 2.0.0

## Breaking changes

- Removed `HandlesResources` attribute from the `Process` class, which duplicates `handlesResources`
- Change default `Dataflow.dstPort` attribute value from `10000` to `-1`

## New features

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
