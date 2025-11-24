"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight, Home } from "lucide-react";

export default function Breadcrumbs() {
    const pathname = usePathname();

    if (!pathname || pathname === "/") return null;

    const segments = pathname.split("/").filter(Boolean);

    // Map common paths to readable labels
    const getLabel = (segment: string, index: number, allSegments: string[]) => {
        if (segment === "boards") return "Boards";
        if (segment === "profile") return "Profile";
        if (segment === "search") return "Search";
        if (segment === "notifications") return "Notifications";

        // If it's an ID after "boards", try to decode it or show "Board"
        if (index > 0 && allSegments[index - 1] === "boards") {
            try {
                return decodeURIComponent(segment).replace(/-/g, " ");
            } catch {
                return segment;
            }
        }

        return segment.charAt(0).toUpperCase() + segment.slice(1);
    };

    return (
        <nav aria-label="Breadcrumb" className="flex items-center text-xs text-text-tertiary mb-4 px-4 md:px-0">
            <Link
                href="/"
                className="flex items-center hover:text-primary transition-colors"
            >
                <Home className="h-3 w-3 mr-1" />
                Home
            </Link>

            {segments.map((segment, index) => {
                const href = `/${segments.slice(0, index + 1).join("/")}`;
                const isLast = index === segments.length - 1;
                const label = getLabel(segment, index, segments);

                return (
                    <div key={href} className="flex items-center">
                        <ChevronRight className="h-3 w-3 mx-1 text-border" />
                        {isLast ? (
                            <span className="font-medium text-text-primary truncate max-w-[150px]">
                                {label}
                            </span>
                        ) : (
                            <Link
                                href={href}
                                className="hover:text-primary transition-colors truncate max-w-[100px]"
                            >
                                {label}
                            </Link>
                        )}
                    </div>
                );
            })}
        </nav>
    );
}
