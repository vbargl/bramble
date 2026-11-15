import { useLingui } from "@lingui/react/macro";
import { useRef, useState } from "react";
import { TextField } from "../../../components/ui/text-field";

/** A device's name, edited in place. Enter or leaving the field saves; Escape cancels (null). */
export function DeviceNameField({
	initial,
	onDone,
}: {
	initial: string;
	onDone: (name: string | null) => void;
}) {
	const { t } = useLingui();
	const [value, setValue] = useState(initial);
	// Closing the field can blur it, and that blur must not save what Escape threw away.
	const done = useRef(false);
	const finish = (name: string | null) => {
		if (done.current) return;
		done.current = true;
		onDone(name);
	};
	return (
		<TextField
			size="sm"
			label={t`Device name`}
			value={value}
			maxLength={64}
			autoFocus
			autoComplete="off"
			onChange={(e) => setValue(e.target.value)}
			onKeyDown={(e) => {
				if (e.key === "Enter") finish(value);
				if (e.key === "Escape") finish(null);
			}}
			onBlur={() => finish(value)}
		/>
	);
}
