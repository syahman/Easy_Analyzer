import { useEffect, useState } from "react";
import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
} from "lucide-react";
import { Button } from "./ui/button";
import { Select } from "./ui/select";
import { number } from "../lib/utils";
export function Pagination({
  offset,
  total,
  limit,
  loading = false,
  label = "",
  onPage,
  onSize,
}: {
  offset: number;
  total: number;
  limit: number;
  loading?: boolean;
  label?: string;
  onPage: (offset: number) => void;
  onSize?: (limit: number) => void;
}) {
  const pages = Math.ceil(total / limit),
    current = total ? Math.floor(offset / limit) + 1 : 0;
  const [draft, setDraft] = useState(String(current || 1));
  useEffect(() => setDraft(String(current || 1)), [current, limit]);
  const name = (text: string) => (label ? `${label} ${text}` : text);
  const valid =
    /^\d+$/.test(draft) && Number(draft) >= 1 && Number(draft) <= pages;
  return (
    <nav
      className="pagination"
      aria-label={label ? `${label} pagination` : "Pagination"}
    >
      <span>
        {number(total)} items · Page {current} / {pages}
      </span>
      <div>
        {onSize && (
          <Select
            label={name("Records per page")}
            value={String(limit)}
            disabled={loading}
            onChange={(v) => onSize(Number(v))}
            options={[50, 100, 200].map((value) => ({
              value: String(value),
              label: `${value} / page`,
            }))}
          />
        )}
        <Button
          variant="ghost"
          size="icon"
          aria-label={name("First page")}
          title="First page"
          disabled={loading || !total || offset === 0}
          onClick={() => onPage(0)}
        >
          <ChevronsLeft size={15} />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          aria-label={name("Previous page")}
          title="Previous page"
          disabled={loading || !total || offset === 0}
          onClick={() => onPage(Math.max(0, offset - limit))}
        >
          <ChevronLeft size={15} />
        </Button>
        <form
          className="page-jump"
          onSubmit={(e) => {
            e.preventDefault();
            if (valid && !loading) onPage((Number(draft) - 1) * limit);
          }}
        >
          <input
            type="number"
            aria-label={name("Page number")}
            min="1"
            max={Math.max(1, pages)}
            value={draft}
            disabled={loading || !total}
            onChange={(e) => setDraft(e.target.value)}
          />
          <Button
            type="submit"
            variant="ghost"
            size="sm"
            disabled={loading || !valid}
          >
            Go
          </Button>
        </form>
        <Button
          variant="ghost"
          size="icon"
          aria-label={name("Next page")}
          title="Next page"
          disabled={loading || !total || offset + limit >= total}
          onClick={() => onPage(offset + limit)}
        >
          <ChevronRight size={15} />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          aria-label={name("Last page")}
          title="Last page"
          disabled={loading || !total || offset + limit >= total}
          onClick={() => onPage((pages - 1) * limit)}
        >
          <ChevronsRight size={15} />
        </Button>
      </div>
    </nav>
  );
}
