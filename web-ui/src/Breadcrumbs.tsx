export type BreadcrumbItem = {
  label: string;
  href?: string;
  onNavigate?: () => void;
};

export function Breadcrumbs({
  items,
  label = "Breadcrumb",
  className = "",
}: {
  items: BreadcrumbItem[];
  label?: string;
  className?: string;
}) {
  return (
    <nav className={`breadcrumbs ${className}`.trim()} aria-label={label}>
      <ol>
        {items.map((item, index) => (
          <li key={`${index}:${item.label}`}>
            {index > 0 && <span aria-hidden="true">/</span>}
            {item.href ? (
              <a
                href={item.href}
                onClick={(event) => {
                  if (
                    !item.onNavigate ||
                    event.button !== 0 ||
                    event.metaKey ||
                    event.ctrlKey ||
                    event.shiftKey ||
                    event.altKey
                  )
                    return;
                  event.preventDefault();
                  item.onNavigate();
                }}
              >
                {item.label}
              </a>
            ) : (
              <span
                aria-current={index === items.length - 1 ? "page" : undefined}
              >
                {item.label}
              </span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}
