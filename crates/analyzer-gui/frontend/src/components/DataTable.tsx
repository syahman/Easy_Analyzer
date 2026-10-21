import { useEffect, useRef } from "react";
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from "@tanstack/react-table";
import { Database, LoaderCircle } from "lucide-react";
import { Pagination } from "./Pagination";
import type { Page } from "../types";
export function DataTable<T>({
  page,
  columns,
  id,
  selected,
  onSelect,
  loading = false,
  empty = "No results for the current filter",
  onPage,
  onSize,
  limit = 100,
}: {
  page: Page<T> | null;
  columns: ColumnDef<T>[];
  id: (v: T) => string;
  selected?: string | null;
  onSelect?: (v: T) => void;
  loading?: boolean;
  empty?: string;
  onPage?: (offset: number) => void;
  onSize?: (limit: number) => void;
  limit?: number;
}) {
  const scroller = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (scroller.current) scroller.current.scrollTop = 0;
  }, [page?.offset, limit]);
  const table = useReactTable({
    data: page?.items || [],
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: id,
    manualPagination: true,
    rowCount: page?.total || 0,
  });
  return (
    <div className="data-table">
      <div className="table-scroll" ref={scroller}>
        <table>
          <colgroup>
            {table.getAllLeafColumns().map((c) => (
              <col
                key={c.id}
                style={
                  c.columnDef.size ? { width: c.columnDef.size } : undefined
                }
              />
            ))}
          </colgroup>
          <thead>
            {table.getHeaderGroups().map((group) => (
              <tr key={group.id}>
                {group.headers.map((h) => (
                  <th key={h.id}>
                    {flexRender(h.column.columnDef.header, h.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              <tr
                key={row.id}
                tabIndex={onSelect ? 0 : undefined}
                onClick={() => onSelect?.(row.original)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") onSelect?.(row.original);
                }}
                className={selected === row.id ? "selected" : ""}
              >
                {row.getVisibleCells().map((c) => (
                  <td key={c.id}>
                    {flexRender(c.column.columnDef.cell, c.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {!table.getRowModel().rows.length && (
          <div className="table-empty">
            {loading ? (
              <LoaderCircle className="spin" size={23} />
            ) : (
              <Database size={24} strokeWidth={1.3} />
            )}
            <span>{loading ? "Reading evidence" : empty}</span>
          </div>
        )}
      </div>
      {onPage && (
        <Pagination
          offset={page?.offset || 0}
          total={page?.total || 0}
          limit={limit}
          loading={loading || !page}
          onPage={onPage}
          onSize={onSize}
        />
      )}
    </div>
  );
}
