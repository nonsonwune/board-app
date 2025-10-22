import BoardViewer from '../../../components/board-viewer';

interface BoardPageProps {
  params: Promise<{ boardId: string }>;
}

export default async function BoardPage({ params }: BoardPageProps) {
  const { boardId } = await params;
  return <BoardViewer boardId={boardId} />;
}
