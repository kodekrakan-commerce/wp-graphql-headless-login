<?php
readonly class HeadlessReadonly { public function __construct(public int $id) {} }
interface HeadlessA {}
interface HeadlessB {}
function headless_dnf((HeadlessA&HeadlessB)|null $value): (HeadlessA&HeadlessB)|null { return $value; }
